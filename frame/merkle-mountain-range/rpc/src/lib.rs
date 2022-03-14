// This file is part of Substrate.

// Copyright (C) 2021-2022 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![warn(missing_docs)]
#![warn(unused_crate_dependencies)]

//! Node-specific RPC methods for interaction with Merkle Mountain Range pallet.

use std::{marker::PhantomData, sync::Arc};

use codec::{Codec, Encode};
use jsonrpsee::{
	core::{async_trait, RpcResult},
	proc_macros::rpc,
	types::error::{CallError, ErrorObject},
};
use serde::{Deserialize, Serialize};

use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_core::Bytes;
use sp_mmr_primitives::{BatchProof, Error as MmrError, LeafIndex, Proof};
use sp_runtime::{generic::BlockId, traits::Block as BlockT};

pub use sp_mmr_primitives::MmrApi as MmrRuntimeApi;

const RUNTIME_ERROR: i32 = 8000;
const MMR_ERROR: i32 = 8010;
const LEAF_NOT_FOUND_ERROR: i32 = MMR_ERROR + 1;
const GENERATE_PROOF_ERROR: i32 = MMR_ERROR + 2;

/// Retrieved MMR leaf and its proof.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LeafProof<BlockHash> {
	/// Block hash the proof was generated for.
	pub block_hash: BlockHash,
	/// SCALE-encoded leaf data.
	pub leaf: Bytes,
	/// SCALE-encoded proof data. See [sp_mmr_primitives::Proof].
	pub proof: Bytes,
}

impl<BlockHash> LeafProof<BlockHash> {
	/// Create new `LeafProof` from given concrete `leaf` and `proof`.
	pub fn new<Leaf, MmrHash>(block_hash: BlockHash, leaf: Leaf, proof: Proof<MmrHash>) -> Self
	where
		Leaf: Encode,
		MmrHash: Encode,
	{
		Self { block_hash, leaf: Bytes(leaf.encode()), proof: Bytes(proof.encode()) }
	}
}

/// Retrieved MMR leaves and their proof.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LeafBatchProof<BlockHash> {
	/// Block hash the proof was generated for.
	pub block_hash: BlockHash,
	/// SCALE-encoded vector of `LeafData`.
	pub leaves: Bytes,
	/// SCALE-encoded proof data. See [sp_mmr_primitives::BatchProof].
	pub proof: Bytes,
}

impl<BlockHash> LeafBatchProof<BlockHash> {
	/// Create new `LeafBatchProof` from a given vector of `Leaf` and a
	/// [sp_mmr_primitives::BatchProof].
	pub fn new<Leaf, MmrHash>(
		block_hash: BlockHash,
		leaves: Vec<Leaf>,
		proof: BatchProof<MmrHash>,
	) -> Self
	where
		Leaf: Encode,
		MmrHash: Encode,
	{
		Self { block_hash, leaves: Bytes(leaves.encode()), proof: Bytes(proof.encode()) }
	}
}

/// MMR RPC methods.
#[rpc(client, server)]
pub trait MmrApi<BlockHash> {
	/// Generate MMR proof for given leaf index.
	///
	/// This method calls into a runtime with MMR pallet included and attempts to generate
	/// MMR proof for leaf at given `leaf_index`.
	/// Optionally, a block hash at which the runtime should be queried can be specified.
	///
	/// Returns the (full) leaf itself and a proof for this leaf (compact encoding, i.e. hash of
	/// the leaf). Both parameters are SCALE-encoded.
	#[method(name = "mmr_generateProof")]
	fn generate_proof(
		&self,
		leaf_index: LeafIndex,
		at: Option<BlockHash>,
	) -> RpcResult<LeafProof<BlockHash>>;

	/// Generate MMR proof for the given leaf indices.
	///
	/// This method calls into a runtime with MMR pallet included and attempts to generate
	/// MMR proof for a set of leaves at the given `leaf_indices`.
	/// Optionally, a block hash at which the runtime should be queried can be specified.
	///
	/// Returns the leaves and a proof for these leaves (compact encoding, i.e. hash of
	/// the leaves). Both parameters are SCALE-encoded.
	/// The order of entries in the `leaves` field of the returned struct
	/// is the same as the order of the entries in `leaf_indices` supplied
	#[method(name = "mmr_generateBatchProof")]
	fn generate_batch_proof(
		&self,
		leaf_indices: Vec<LeafIndex>,
		at: Option<BlockHash>,
	) -> RpcResult<LeafBatchProof<BlockHash>>;
}

/// MMR RPC methods.
pub struct Mmr<Client, Block> {
	client: Arc<Client>,
	_marker: PhantomData<Block>,
}

impl<C, B> Mmr<C, B> {
	/// Create new `Mmr` with the given reference to the client.
	pub fn new(client: Arc<C>) -> Self {
		Self { client, _marker: Default::default() }
	}
}

#[async_trait]
impl<Client, Block, MmrHash> MmrApiServer<<Block as BlockT>::Hash> for Mmr<Client, (Block, MmrHash)>
where
	Block: BlockT,
	Client: Send + Sync + 'static + ProvideRuntimeApi<Block> + HeaderBackend<Block>,
	Client::Api: MmrRuntimeApi<Block, MmrHash>,
	MmrHash: Codec + Send + Sync + 'static,
{
	fn generate_proof(
		&self,
		leaf_index: LeafIndex,
		at: Option<<Block as BlockT>::Hash>,
	) -> RpcResult<LeafProof<Block::Hash>> {
		let api = self.client.runtime_api();
		let block_hash = at.unwrap_or_else(|| self.client.info().best_hash);

		let (leaf, proof) = api
			.generate_proof_with_context(
				&BlockId::hash(block_hash),
				sp_core::ExecutionContext::OffchainCall(None),
				leaf_index,
			)
			.map_err(runtime_error_into_rpc_error)?
			.map_err(mmr_error_into_rpc_error)?;

		Ok(LeafProof::new(block_hash, leaf, proof))
	}

	fn generate_batch_proof(
		&self,
		leaf_indices: Vec<LeafIndex>,
		at: Option<<Block as BlockT>::Hash>,
	) -> RpcResult<LeafBatchProof<<Block as BlockT>::Hash>> {
		let api = self.client.runtime_api();
		let block_hash = at.unwrap_or_else(||
			// If the block hash is not supplied assume the best block.
			self.client.info().best_hash);

		let (leaves, proof) = api
			.generate_batch_proof_with_context(
				&BlockId::hash(block_hash),
				sp_core::ExecutionContext::OffchainCall(None),
				leaf_indices,
			)
			.map_err(runtime_error_into_rpc_error)?
			.map_err(mmr_error_into_rpc_error)?;

		Ok(LeafBatchProof::new(block_hash, leaves, proof))
	}
}

/// Converts a mmr-specific error into a [`CallError`].
fn mmr_error_into_rpc_error(err: MmrError) -> CallError {
	let data = format!("{:?}", err);
	match err {
		MmrError::LeafNotFound => CallError::Custom(ErrorObject::owned(
			LEAF_NOT_FOUND_ERROR,
			"Leaf was not found",
			Some(data),
		)),
		MmrError::GenerateProof => CallError::Custom(ErrorObject::owned(
			GENERATE_PROOF_ERROR,
			"Error while generating the proof",
			Some(data),
		)),
		_ => CallError::Custom(ErrorObject::owned(MMR_ERROR, "Unexpected MMR error", Some(data))),
	}
}

/// Converts a runtime trap into a [`CallError`].
fn runtime_error_into_rpc_error(err: impl std::fmt::Debug) -> CallError {
	CallError::Custom(ErrorObject::owned(
		RUNTIME_ERROR,
		"Runtime trapped",
		Some(format!("{:?}", err)),
	))
}

#[cfg(test)]
mod tests {
	use super::*;
	use hex_literal::hex;
	use sp_core::{bytes::to_hex, H256};
	use sp_runtime::traits::Keccak256;

	#[test]
	fn should_serialize_leaf_proof() {
		// given
		let leaf = vec![1_u8, 2, 3, 4];
		let proof = Proof {
			leaf_index: 1,
			leaf_count: 9,
			items: vec![H256::repeat_byte(1), H256::repeat_byte(2)],
		};

		let leaf_proof = LeafProof::new(H256::repeat_byte(0), leaf, proof);

		// when
		let actual = serde_json::to_string(&leaf_proof).unwrap();

		// then
		assert_eq!(
			actual,
			r#"{"blockHash":"0x0000000000000000000000000000000000000000000000000000000000000000","leaf":"0x1001020304","proof":"0x010000000000000009000000000000000801010101010101010101010101010101010101010101010101010101010101010202020202020202020202020202020202020202020202020202020202020202"}"#
		);
	}

	#[test]
	fn should_serialize_leaf_batch_proof() {
		// given
		let leaf = vec![1_u8, 2, 3, 4];
		let proof = BatchProof {
			leaf_indices: vec![1],
			leaf_count: 9,
			items: vec![H256::repeat_byte(1), H256::repeat_byte(2)],
		};

		let leaf_proof = LeafBatchProof::new(H256::repeat_byte(0), vec![leaf], proof);

		// when
		let actual = serde_json::to_string(&leaf_proof).unwrap();

		// then
		assert_eq!(
			actual,
			r#"{"blockHash":"0x0000000000000000000000000000000000000000000000000000000000000000","leaves":"0x041001020304","proof":"0x04010000000000000009000000000000000801010101010101010101010101010101010101010101010101010101010101010202020202020202020202020202020202020202020202020202020202020202"}"#
		);
	}

	#[test]
	fn should_deserialize_leaf_proof() {
		// given
		let expected = LeafProof {
			block_hash: H256::repeat_byte(0),
			leaf: Bytes(vec![1_u8, 2, 3, 4].encode()),
			proof: Bytes(
				Proof {
					leaf_index: 1,
					leaf_count: 9,
					items: vec![H256::repeat_byte(1), H256::repeat_byte(2)],
				}
				.encode(),
			),
		};

		// when
		let actual: LeafProof<H256> = serde_json::from_str(r#"{
			"blockHash":"0x0000000000000000000000000000000000000000000000000000000000000000",
			"leaf":"0x1001020304",
			"proof":"0x010000000000000009000000000000000801010101010101010101010101010101010101010101010101010101010101010202020202020202020202020202020202020202020202020202020202020202"
		}"#).unwrap();

		// then
		assert_eq!(actual, expected);
	}

	#[test]
	fn should_deserialize_leaf_batch_proof() {
		// given
		let expected = LeafBatchProof {
			block_hash: H256::repeat_byte(0),
			leaves: Bytes(vec![vec![1_u8, 2, 3, 4]].encode()),
			proof: Bytes(
				BatchProof {
					leaf_indices: vec![1],
					leaf_count: 9,
					items: vec![H256::repeat_byte(1), H256::repeat_byte(2)],
				}
				.encode(),
			),
		};

		// when
		let actual: LeafBatchProof<H256> = serde_json::from_str(r#"{
			"blockHash":"0x0000000000000000000000000000000000000000000000000000000000000000",
			"leaves":"0x041001020304",
			"proof":"0x04010000000000000009000000000000000801010101010101010101010101010101010101010101010101010101010101010202020202020202020202020202020202020202020202020202020202020202"
		}"#).unwrap();

		// then
		assert_eq!(actual, expected);
	}

	#[test]
	fn verify_leaf_batch_proof() {
		let proof = hex!("085100000000000000550000000000000059000000000000001c919f74633e8c8e36a84bf395798907c3b6ae5a3153a44ab0a7da4cbf3875ed73ad4360bcdefc245c0442db20542649b5be9b8e8e663615f21848ff1d93698696f0bed286e1e4847f789862436dca72cecbedc8431c472fb9a8fb4c6a2b46e406982af3b60f75914ec56e6b8aec1fa7e2bb90e56d4fe84983c15111a2967e13fda834df1c838ea86baab278721e725237cdeb00a5c4b321d6cbb1be1f34a29def22229501db81a5322cb0b44d773b24d22ff90cf9e2a6e81fdb44198d55999b9703aad4830a9be608ce5a19a67668b22d7f17ec49621c9acbe608d721d0f16336").to_vec();
		let leaves = hex!("08c5010051000000d4d6e57a1501adb3b6913e6dcf1daa94e33b34874db5217c7cda675dc2f2ceb2010000000000000002000000697ea2a8fe5b03468548a7a413424a6292ab44a82a6f5cc594c3fa7dda7ce402aed43d163a98d6e7a734d6c499434c5ed527bdb1d91a2aa497f3ac8a4525c6ea5100000000000000c501005500000059583e0535a9976fef5a6e45207193e931b954b7aee6389996964404869ddeab010000000000000002000000697ea2a8fe5b03468548a7a413424a6292ab44a82a6f5cc594c3fa7dda7ce402f966a1030ff01a79d91a64e28f71db529fdf0f7a6062b963853020e8345eb20f5500000000000000").to_vec();
		let mmr_root = H256::from([
			156, 210, 34, 255, 181, 219, 85, 193, 33, 150, 251, 202, 203, 239, 8, 16, 103, 229,
			217, 93, 230, 146, 128, 41, 30, 54, 10, 212, 146, 75, 97, 29,
		]);

		println!("{}", to_hex(&mmr_root[..], false));
		let batch_proof: BatchProof<H256> = codec::Decode::decode(&mut &proof[..]).unwrap();

		let leaves: Vec<(Vec<u8>, u64)> = codec::Decode::decode(&mut &leaves[..]).unwrap();

		let mmr_leaves = leaves
			.into_iter()
			.map(|(l, i)| {
				let hash = sp_core::keccak_256(&l[..]);
				println!("leaf: {}, {:?}", i, hash);
				pallet_mmr::mmr::Node::<Keccak256, ()>::Hash(H256::from(hash))
			})
			.collect::<Vec<_>>();
		pallet_mmr::verify_leaves_proof(mmr_root, mmr_leaves, batch_proof).unwrap()
	}
}
