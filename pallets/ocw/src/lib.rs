#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;
use frame_support::traits::Currency;


#[frame_support::pallet]
pub mod pallet {
	//! A demonstration of an offchain worker that sends onchain callbacks
	use core::{convert::TryInto};
	use parity_scale_codec::{Decode, Encode};
	use frame_support::pallet_prelude::*;
	use frame_support::traits::{Currency, OnFinalize, Randomness, ReservableCurrency};
	use frame_support::traits::ExistenceRequirement::KeepAlive;
	use frame_system::{pallet_prelude::*, offchain::{
		AppCrypto, CreateSignedTransaction, SendSignedTransaction, SendUnsignedTransaction,
		SignedPayload, Signer, SigningTypes, SubmitTransaction,
	}, Origin};
	use sp_core::{crypto::KeyTypeId, H256};
	use sp_runtime::{
		offchain::{
			http,
			storage::StorageValueRef,
			storage_lock::{BlockAndTime, StorageLock},
			Duration,
		},
		traits::BlockNumberProvider,
		transaction_validity::{
			InvalidTransaction, TransactionSource, TransactionValidity, ValidTransaction,
		},
		RuntimeDebug,
	};
	use sp_std::{collections::vec_deque::VecDeque, prelude::*, str};

	use serde::{Deserialize, Deserializer};
	use sp_runtime::DispatchError::BadOrigin;
	use crate::Event::TaskCompleted;

	/// Defines application identifier for crypto keys of this module.
	///
	/// Every module that deals with signatures needs to declare its unique identifier for
	/// its crypto keys.
	/// When an offchain worker is signing transactions it's going to request keys from type
	/// `KeyTypeId` via the keystore to sign the transaction.
	/// The keys can be inserted manually via RPC (see `author_insertKey`).
	pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"demo");
	/// Based on the above `KeyTypeId` we need to generate a pallet-specific crypto type wrapper.
	/// We can utilize the supported crypto kinds (`sr25519`, `ed25519` and `ecdsa`) and augment
	/// them with the pallet-specific identifier.
	pub mod crypto {
		use crate::KEY_TYPE;
		use sp_core::sr25519::Signature as Sr25519Signature;
		use sp_std::prelude::*;
		use sp_runtime::{
			app_crypto::{app_crypto, sr25519},
			traits::Verify, MultiSignature, MultiSigner
		};

		app_crypto!(sr25519, KEY_TYPE);

		pub struct TestAuthId;
		// implemented for runtime
		impl frame_system::offchain::AppCrypto<MultiSigner, MultiSignature> for TestAuthId {
			type RuntimeAppPublic = Public;
			type GenericSignature = sp_core::sr25519::Signature;
			type GenericPublic = sp_core::sr25519::Public;
		}

		// implemented for mock runtime in test
		impl frame_system::offchain::AppCrypto<<Sr25519Signature as Verify>::Signer, Sr25519Signature>
		for TestAuthId
		{
			type RuntimeAppPublic = Public;
			type GenericSignature = sp_core::sr25519::Signature;
			type GenericPublic = sp_core::sr25519::Public;
		}
	}

	type TaskId = H256;
	type TaskInput = Vec<u64>;
	type TaskResult = u64;

	pub type BalanceOf<T> = <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;
	pub type NegativeImbalanceOf<T> = <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::NegativeImbalance;

	const TASK_FEE: u32 = 100;
	const WORKER_FEE: u32 = 100;


	#[pallet::config]
	pub trait Config: frame_system::Config + CreateSignedTransaction<Call<Self>> {
		/// The overarching event type.
		type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
		/// The overarching dispatch call type.
		type Call: From<Call<Self>>;
		/// The identifier type for an offchain worker.
		type AuthorityId: AppCrypto<Self::Public, Self::Signature>;

		/// The currency in which the crowdfunds will be denominated
		type Currency: ReservableCurrency<Self::AccountId>;
		type TaskIdRandomness: Randomness<H256, BlockNumberFor<Self>>;
		type WorkerAssignmentRandomness: Randomness<H256, BlockNumberFor<Self>>;
	}

	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
	pub struct Pallet<T>(_);

	// The pallet's runtime storage items.
	// https://substrate.dev/docs/en/knowledgebase/runtime/storage
	#[pallet::storage]
	#[pallet::getter(fn tasks)]
	pub type Tasks<T: Config> = StorageMap<_, Blake2_128Concat, TaskId, (T::AccountId, TaskInput)>;

	#[pallet::storage]
	#[pallet::getter(fn task_assignments)]
	pub type TaskAssignments<T: Config> = StorageMap<_, Blake2_128Concat, T::AccountId, Vec<TaskId>>;

	#[pallet::storage]
	#[pallet::getter(fn workers)]
	pub type Workers<T: Config> = StorageMap<_, Blake2_128Concat, T::AccountId, bool>;

	#[pallet::storage]
	#[pallet::getter(fn nonce)]
	pub(super) type Nonce<T: Config> = StorageValue<_, u32, ValueQuery>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		NewTask(TaskId, TaskInput),
		TaskCompleted(TaskId, TaskResult),
		TaskFailed(TaskId),
	}

	// Errors inform users that something went wrong.
	#[pallet::error]
	pub enum Error<T> {
		// Error returned when not sure which ocw function to executed
		InsufficientBalance,
		TaskSubmissionFailed,
		TaskAssignmentFailed,
		NoLocalAccount,
	}

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		fn offchain_worker(block_number: T::BlockNumber) {
			log::info!("Doing all computations.");

		}
	}
	#[pallet::call]
	impl<T: Config> Pallet<T> {
		#[pallet::weight(10000)]
		pub fn submit_task(origin: OriginFor<T>, input: TaskInput) -> DispatchResult {
			let who = ensure_signed(origin)?;
			log::info!("submit_task: ({:?}, {:?})", who, input);
			match Self::assign_task(&who, &input) {
				Ok(task_id) => {
					Self::deposit_event(Event::NewTask(task_id, input));
					T::Currency::reserve(&who, TASK_FEE.into());
					Ok(())
				},
				Err(e) => Err(BadOrigin),
			}
		}

		#[pallet::weight(10000)]
		pub fn submit_task_result(origin: OriginFor<T>, task_id: TaskId, result: TaskResult)->DispatchResult{
			let who = ensure_signed(origin)?;
			if let Ok((task_owner, task_index)) = Self::validate_task_result_submission(&who, task_id){
				<TaskAssignments<T>>::mutate_exists(&who, |maybe_tasks|{
					match maybe_tasks{
						Some(tasks) => {
							(*tasks).remove(task_index);
						},
						None => (),
					}
				});
				<Tasks<T>>::remove(task_id);
				Self::deposit_event(Event::TaskCompleted(task_id, result));
				let fee: BalanceOf<T> = TASK_FEE.into();
				T::Currency::unreserve(&task_owner, fee);
				match T::Currency::transfer(&task_owner, &who, fee, KeepAlive){
					Ok(_) => Ok(()),
					Err(e) => Err(e),
				}
			}else{
				Err(BadOrigin)
			}
		}


		#[pallet::weight(10000)]
		pub fn submit_task_failure(origin: OriginFor<T>, task_id: TaskId)->DispatchResult{
			let who = ensure_signed(origin)?;
			if let Ok((task_owner, task_index)) = Self::validate_task_result_submission(&who, task_id){
				<TaskAssignments<T>>::mutate_exists(&who, |maybe_tasks|{
					match maybe_tasks{
						Some(tasks) => {
							(*tasks).remove(task_index);
						},
						None => (),
					}
				});
				<Tasks<T>>::remove(task_id);
				Self::deposit_event(Event::TaskFailed(task_id));
				let fee: BalanceOf<T> = TASK_FEE.into();
				T::Currency::unreserve(&task_owner, fee);
				Ok(())
			}else{
				Err(BadOrigin)
			}
		}

		#[pallet::weight(10000)]
		pub fn start_worker(origin: OriginFor<T>) -> DispatchResult{
			let who = ensure_signed(origin)?;
			if T::Currency::can_reserve(&who, WORKER_FEE.into()){
				if <Workers<T>>::contains_key(&who){
					<Workers<T>>::mutate(&who, {|maybe_status|
						match maybe_status{
							Some(status) => *status = true,
							None => ()
						}
					});
				}else{
					<Workers<T>>::insert(&who, true);
				}
				T::Currency::reserve(&who, WORKER_FEE.into());
				Ok(())
			}else{
				Err(BadOrigin)
			}
		}

		#[pallet::weight(10000)]
		pub fn stop_worker(origin: OriginFor<T>) -> DispatchResult{
			let who = ensure_signed(origin)?;
			if <Workers<T>>::contains_key(&who){
				<Workers<T>>::mutate(&who, {|maybe_status|
					match maybe_status{
						Some(status) => *status = false,
						None => ()
					}
				});
				T::Currency::unreserve(&who, WORKER_FEE.into());
			}else{
				<Workers<T>>::insert(&who, false);
			}
			Ok(())
		}


	}

	impl<T: Config> Pallet<T> {
		/// Append a new number to the tail of the list, removing an element from the head if reaching
		///   the bounded length.
		///
		fn compute_all_tasks() -> Result<(), Error<T>>{
			let signer = Signer::<T, T::AuthorityId>::all_accounts();
			if !signer.can_sign() {
				return Err(<Error<T>>::NoLocalAccount);
			}
			for (worker, task_ids) in <TaskAssignments<T>>::iter(){
				for task_id in task_ids.iter() {
					if let Some((task_owner, task_input)) = <Tasks<T>>::get(&task_id){
						match Self::compute_one_task(&task_id, &task_input) {
							Ok(_) => continue,
							Err(e) => continue,
						}
					}
				}
			}
			Ok(())
		}

		fn compute_one_task(task_id: &TaskId, task_input: &TaskInput)->DispatchResult{
			let result = task_input.iter().sum();
			let signer = Signer::<T, T::AuthorityId>::all_accounts();
			let results = signer.send_signed_transaction(|_account| {
				Call::submit_task_result{task_id: *task_id, result: result }
			});
			Ok(())
		}

		fn validate_task_result_submission(who: &T::AccountId, task_id: TaskId) -> Result<(T::AccountId, usize), Error<T>>{
			if let Some((task_owner, _)) = <Tasks<T>>::get(task_id) {
				if <TaskAssignments<T>>::contains_key(&who) {
					if let Some(task_ids) = <TaskAssignments<T>>::get(&who) {
						if let Some(index) = task_ids.iter().position(|&id| id == task_id) {
							return Ok((task_owner, index))
						}
					}
				}
			}
			Err(<Error<T>>::TaskSubmissionFailed)
		}
		fn assign_task(who: &T::AccountId, task_input: &TaskInput) -> Result<TaskId, Error<T>>{
			let mut subject = Self::encode_and_update_nonce();

			let mut random_result = T::TaskIdRandomness::random(&subject);
			while <Tasks<T>>::contains_key(random_result.0){
				subject = Self::encode_and_update_nonce();
				random_result = T::TaskIdRandomness::random(&subject);
			}
			let task_id = random_result.0;
			<Tasks<T>>::insert(task_id, (who, task_input));

			let mut workers = <Vec<T::AccountId>>::new();

			for (worker, status) in <Workers<T>>::iter(){
				if status{
					workers.push(worker)
				}
			}

			subject = Self::encode_and_update_nonce();
			random_result = T::WorkerAssignmentRandomness::random(&subject);
			let hash = random_result.0;
			let random_usize: usize = hash.to_fixed_bytes().iter().fold(0, |sum, i| sum + (*i as usize));

			let index = random_usize / workers.iter().count();
			if let Some(worker) = workers.get(index) {
				if <TaskAssignments<T>>::contains_key(worker) {
					<TaskAssignments<T>>::mutate_exists(worker, {
						|maybe_task_ids|
							match maybe_task_ids {
								Some(task_ids) => (*task_ids).push(task_id),
								None => ()
							}
					})
				} else {
					<TaskAssignments<T>>::insert(worker, vec![task_id])
				}
				Ok(task_id)
			}else{
				Err(<Error<T>>::TaskAssignmentFailed)
			}
		}

		fn encode_and_update_nonce() -> Vec<u8> {
			let nonce = Nonce::<T>::get();
			Nonce::<T>::put(nonce.wrapping_add(1));
			nonce.encode()
		}

	}
}
