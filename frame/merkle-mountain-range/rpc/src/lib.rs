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

//! Node-specific RPC methods for interaction with Merkle Mountain Range pallet.

use std::{fmt::Debug, sync::Arc};

use codec::{Codec, Encode};
use jsonrpc_core::{Error, ErrorCode, Result};
use jsonrpc_derive::rpc;
use serde::{Deserialize, Serialize};

use pallet_mmr_primitives::{BatchProof, Error as MmrError, Proof};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_core::Bytes;
use sp_runtime::{generic::BlockId, traits::Block as BlockT};

pub use pallet_mmr_primitives::{LeafIndex, MmrApi as MmrRuntimeApi};
use sp_core::bytes::to_hex;

/// Retrieved MMR leaf and its proof.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LeafProof<BlockHash> {
	/// Block hash the proof was generated for.
	pub block_hash: BlockHash,
	/// SCALE-encoded leaf data.
	pub leaf: Bytes,
	/// SCALE-encoded proof data. See [pallet_mmr_primitives::Proof].
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

/// Retrieved MMR leaf and its proof.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LeafBatchProof<BlockHash> {
	/// Block hash the proof was generated for.
	pub block_hash: BlockHash,
	/// SCALE-encoded vector of leaf index and leaf data `(LeafData, LeafIndex)`.
	pub leaves: Bytes,
	/// SCALE-encoded proof data. See [pallet_mmr_primitives::BatchProof].
	pub proof: Bytes,
}

impl<BlockHash> LeafBatchProof<BlockHash> {
	/// Create new `LeafBatchProof` from a given vector of (`Leaf`,
	/// [pallet_mmr_primitives::LeafIndex]) and a [pallet_mmr_primitives::BatchProof].
	pub fn new<Leaf: Debug, MmrHash>(
		block_hash: BlockHash,
		leaves: Vec<(Leaf, LeafIndex)>,
		proof: BatchProof<MmrHash>,
	) -> Self
	where
		Leaf: Encode,
		MmrHash: Encode,
	{
		println!("{:#?}\n\n{:#?}", leaves, to_hex(&leaves.encode(), true));
		Self { block_hash, leaves: Bytes(leaves.encode()), proof: Bytes(proof.encode()) }
	}
}

/// MMR RPC methods.
#[rpc]
pub trait MmrApi<BlockHash> {
	/// Generate MMR proof for given leaf index.
	///
	/// This method calls into a runtime with MMR pallet included and attempts to generate
	/// MMR proof for leaf at given `leaf_index`.
	/// Optionally, a block hash at which the runtime should be queried can be specified.
	///
	/// Returns the (full) leaf itself and a proof for this leaf (compact encoding, i.e. hash of
	/// the leaf). Both parameters are SCALE-encoded.
	#[rpc(name = "mmr_generateProof")]
	fn generate_proof(
		&self,
		leaf_index: LeafIndex,
		at: Option<BlockHash>,
	) -> Result<LeafProof<BlockHash>>;

	/// Generate MMR proof for the given leaf indices.
	///
	/// This method calls into a runtime with MMR pallet included and attempts to generate
	/// MMR proof for a set of leaves at the given `leaf_indices`.
	/// Optionally, a block hash at which the runtime should be queried can be specified.
	///
	/// Returns the leaves and a proof for these leaves (compact encoding, i.e. hash of
	/// the leaves). Both parameters are SCALE-encoded.
	#[rpc(name = "mmr_generateBatchProof")]
	fn generate_batch_proof(
		&self,
		leaf_indices: Vec<LeafIndex>,
		at: Option<BlockHash>,
	) -> Result<LeafBatchProof<BlockHash>>;
}

/// An implementation of MMR specific RPC methods.
pub struct Mmr<C, B> {
	client: Arc<C>,
	_marker: std::marker::PhantomData<B>,
}

impl<C, B> Mmr<C, B> {
	/// Create new `Mmr` with the given reference to the client.
	pub fn new(client: Arc<C>) -> Self {
		Self { client, _marker: Default::default() }
	}
}

impl<C, Block, MmrHash> MmrApi<<Block as BlockT>::Hash> for Mmr<C, (Block, MmrHash)>
where
	Block: BlockT,
	C: Send + Sync + 'static + ProvideRuntimeApi<Block> + HeaderBackend<Block>,
	C::Api: MmrRuntimeApi<Block, MmrHash>,
	MmrHash: Codec + Send + Sync + 'static,
{
	fn generate_proof(
		&self,
		leaf_index: LeafIndex,
		at: Option<<Block as BlockT>::Hash>,
	) -> Result<LeafProof<<Block as BlockT>::Hash>> {
		let api = self.client.runtime_api();
		let block_hash = at.unwrap_or_else(||
			// If the block hash is not supplied assume the best block.
			self.client.info().best_hash);

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
	) -> Result<LeafBatchProof<<Block as BlockT>::Hash>> {
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

const RUNTIME_ERROR: i64 = 8000;
const MMR_ERROR: i64 = 8010;

/// Converts a mmr-specific error into an RPC error.
fn mmr_error_into_rpc_error(err: MmrError) -> Error {
	match err {
		MmrError::LeafNotFound => Error {
			code: ErrorCode::ServerError(MMR_ERROR + 1),
			message: "Leaf was not found".into(),
			data: Some(format!("{:?}", err).into()),
		},
		MmrError::GenerateProof => Error {
			code: ErrorCode::ServerError(MMR_ERROR + 2),
			message: "Error while generating the proof".into(),
			data: Some(format!("{:?}", err).into()),
		},
		_ => Error {
			code: ErrorCode::ServerError(MMR_ERROR),
			message: "Unexpected MMR error".into(),
			data: Some(format!("{:?}", err).into()),
		},
	}
}

/// Converts a runtime trap into an RPC error.
fn runtime_error_into_rpc_error(err: impl std::fmt::Debug) -> Error {
	Error {
		code: ErrorCode::ServerError(RUNTIME_ERROR),
		message: "Runtime trapped".into(),
		data: Some(format!("{:?}", err).into()),
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use hex_literal::hex;
	use pallet_mmr_primitives::DataOrHash;
	use sp_core::{bytes::from_hex, KeccakHasher, H256};

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

		let leaf_proof = LeafBatchProof::new(H256::repeat_byte(0), vec![(leaf, 1)], proof);

		// when
		let actual = serde_json::to_string(&leaf_proof).unwrap();
		// then
		assert_eq!(
			actual,
			r#"{"blockHash":"0x0000000000000000000000000000000000000000000000000000000000000000","leaves":"0x0410010203040100000000000000","proof":"0x04010000000000000009000000000000000801010101010101010101010101010101010101010101010101010101010101010202020202020202020202020202020202020202020202020202020202020202"}"#
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
			leaves: Bytes(vec![(vec![1_u8, 2, 3, 4], 1)].encode()),
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
			"leaves":"0x04100102030401000000",
			"proof":"0x04010000000000000009000000000000000801010101010101010101010101010101010101010101010101010101010101010202020202020202020202020202020202020202020202020202020202020202"
		}"#).unwrap();

		// then
		assert_eq!(actual, expected);
	}

	#[test]
	fn deserialize_leaf_batch_proof() {
		use beefy_primitives::mmr::MmrLeaf;

		type Leaf = MmrLeaf<u32, H256, H256>;

		let bytes = from_hex("0x0cc50100090000009744ea94eedfcf1ae50fc4edacfd6c1db8ed345654246792b9bd60b8268cfa3a010000000000000005000000baa93c7834125ee3120bac6e3342bd3f28611110ad21ab6075367abdffefeb0914b3edb9d6a95a4881aebc7f0ee878745a687ca45f50dbf2448b8e3b5d5483600900000000000000c501000e00000014e259b3fd4065f330b10caad83841be639e74d1cab554686328932bf5718944010000000000000005000000baa93c7834125ee3120bac6e3342bd3f28611110ad21ab6075367abdffefeb0914b3edb9d6a95a4881aebc7f0ee878745a687ca45f50dbf2448b8e3b5d5483600e00000000000000c5010010000000ad76138c189ab47863fb04908ad40930641dd9eceb436d8ec691a14a1f07212f010000000000000005000000baa93c7834125ee3120bac6e3342bd3f28611110ad21ab6075367abdffefeb0907e56e2c47ccdf885d359310f3a43192b77e32a7d32773e780d0bcfc6a72ebaf1000000000000000").unwrap();

		let leaves: Vec<(Vec<u8>, u64)> = codec::Decode::decode(&mut &bytes[..]).unwrap();

		let leaves = leaves
			.into_iter()
			.map(|(encoded, index)| {
				let leaf: Leaf = codec::Decode::decode(&mut &encoded[..]).unwrap();
				(leaf, index)
			})
			.collect::<Vec<_>>();

		println!("leaf: {:?}", hex!("03b7076fc071f631787d64ddbd93d3e2"));
	}

	#[test]
	fn test_multi_leaf_mmr_proof() {
		let mmr_root = H256::from([
			72, 183, 40, 135, 139, 221, 74, 166, 201, 0, 52, 167, 117, 108, 17, 181, 114, 52, 217,
			146, 200, 40, 236, 116, 241, 209, 1, 223, 30, 128, 62, 112,
		]);
		let block_hash =
			H256::from(hex!("04e44ea53db9c59545fbb7bc04881fd4c6327029ee7751eee32e78409d4827b7"));
		let leaves = hex!("10c50100bd020000dbd670705fddee2d22d0d3cdced8734aa8c8374197eaf1493f9fb86e7fbeba0f010000000000000005000000baa93c7834125ee3120bac6e3342bd3f28611110ad21ab6075367abdffefeb0975e8469015638c96e3d9942cb35297b28d0cca7add9932c5a7354fa302d6f2e3bd02000000000000c50100be020000a76a43d5b7bf9bfa6c7562ebd35019f7709910a3f76464688f62717b13b20fe8010000000000000005000000baa93c7834125ee3120bac6e3342bd3f28611110ad21ab6075367abdffefeb0975e8469015638c96e3d9942cb35297b28d0cca7add9932c5a7354fa302d6f2e3be02000000000000c50100bf0200006d0ab0459bf2a9305e048805fbc9bc58b7e9454906c2e94b6d981f0e8ceb3180010000000000000005000000baa93c7834125ee3120bac6e3342bd3f28611110ad21ab6075367abdffefeb091b8751c2c1962bde4b57548c1bdef9ef2efcf93730e130036feee3f944bec9edbf02000000000000c50100c0020000d6aaaaa38e330ac1500a22d0fe382ffe2ca9f95161f479dca2e56038696ee343010000000000000005000000baa93c7834125ee3120bac6e3342bd3f28611110ad21ab6075367abdffefeb091b8751c2c1962bde4b57548c1bdef9ef2efcf93730e130036feee3f944bec9edc002000000000000").to_vec();
		let proof = hex!("10bd02000000000000be02000000000000bf02000000000000c002000000000000e903000000000000380b69447305465f8796365fe6035c938e8307482a7eb81d312c74e3bdd4d06e6f861ff8ff2a2c35ba80caf31bbb1d5042133a61b8371af548477d7cf2fc7456ba2c831a65e8ca11b67a84f4b36a9cacb86a27b30e0cc0f10b7a4d406bbcf331e881ae35265781aa57e7619352caad12c681d6c07157f337f5b57a52491475289823ebb41b1af8e1213ae3159bd422d8b421d2813435d89c2dde3b3e201940a49eb282a3bda4a8cf9bef677ae1b49dc211cf25473e02fbf4aca9257552d91bb9763dca3cf547d4d15d53e4c9ee730e3acc8b3705359cbc2857eceea31121ed6706a0c991631e945495269afa5b3759915e77b62add69c1849ac742917e62922819b5c14bffd531d4ff99ef95b9f2e897d64e0e027439334d63cdb7d3ec0c988fa1aed09fb5b47b41a2e27946eecead11062188fb0353b813c1e74c23943a0497f9a5a92a54b9292f657ce45b9bcc699d4eac12a587f19878c51bb338c3c9d84f4481e964f7f7480b0ab9da1e691359b03c003cb3c2f5dc4a29ba9610167f0d782caad6b08a2ec0e74a66afea72837b5e070d18c5e79f0c1fc35fc9c5f0645811bcdaf53cb132d461ea60f4fe62f5a3fc1aa723f4854c067d84a3b1e26c93398bf9").to_vec();

		let proof: BatchProof<H256> = codec::Decode::decode(&mut &proof[..]).unwrap();
		use beefy_primitives::mmr::MmrLeaf;

		type Leaf = MmrLeaf<u32, H256, H256>;

		let leaves: Vec<(Vec<u8>, u64)> = codec::Decode::decode(&mut &leaves[..]).unwrap();

		let leaves = leaves
			.into_iter()
			.map(|(encoded, index)| {
				let leaf: Leaf = codec::Decode::decode(&mut &encoded[..]).unwrap();
				(leaf, index)
			})
			.collect::<Vec<_>>();
		let mmr_leaves = leaves
			.into_iter()
			.map(|(leaf, _)| DataOrHash::<sp_runtime::traits::Keccak256, _>::Data(leaf))
			.collect::<Vec<_>>();
		pallet_mmr::verify_leaves_proof(mmr_root, mmr_leaves, proof).unwrap();
	}
}
