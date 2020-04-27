// Copyright 2019-2020 Parity Technologies (UK) Ltd.
// This file is part of Substrate.

// Substrate is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Substrate is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Substrate.  If not, see <http://www.gnu.org/licenses/>.

use criterion::{Criterion, Throughput, BenchmarkId, criterion_group, criterion_main, black_box};
use sp_arithmetic::biguint::{BigUint, Single};
use sp_arithmetic::{Fixed128, traits::FixedPointNumber};
use sp_arithmetic::helpers_128bit::{divide, multiply_by_rational};
use sp_arithmetic::traits::Saturating;
use num_traits::{Bounded, ops::checked::CheckedMul};
use rand::Rng;

fn random_big_uint(size: usize) -> BigUint {
	let mut rng = rand::thread_rng();
	let digits: Vec<_> = (0..size).map(|_| rng.gen_range(0, Single::max_value())).collect();
	BigUint::from_limbs(&digits)
}

fn bench_op<F: Fn(&BigUint, &BigUint)>(c: &mut Criterion, name: &str, op: F) {
	let mut group = c.benchmark_group(name);

	for size in [2, 4, 6, 8, 10].iter() {
		group.throughput(Throughput::Elements(*size));
		group.bench_with_input(BenchmarkId::from_parameter(size), size, |bencher, &size| {
			let a = random_big_uint(size as usize);
			let b = random_big_uint(size as usize);

			bencher.iter(|| op(&a, &b));
		});
	}
}

fn bench_addition(c: &mut Criterion) {
	bench_op(c, "addition", |a, b| {
		let _ = a.clone().add(&b);
	});
}

fn bench_subtraction(c: &mut Criterion) {
	bench_op(c, "subtraction", |a, b| {
		let _ = a.clone().sub(&b);
	});
}

fn bench_multiplication(c: &mut Criterion) {
	bench_op(c, "multiplication", |a, b| {
		let _ = a.clone().mul(&b);
	});
}

fn bench_division(c: &mut Criterion) {
	let mut group = c.benchmark_group("division");

	for size in [4, 6, 8, 10].iter() {
		group.throughput(Throughput::Elements(*size));
		group.bench_with_input(BenchmarkId::from_parameter(size), size, |bencher, &size| {
			let a = random_big_uint(size as usize);
			let b = random_big_uint(rand::thread_rng().gen_range(2, size as usize));

			bencher.iter(|| {
				let _ = a.clone().div(&b, true);
			});
		});
	}
}

fn bench_checked_mul_int(c: &mut Criterion) {
	let x = Fixed128::max_value();
	c.bench_function("checked_mul_int", |b| b.iter(|| x.checked_mul_int(black_box(20u64))));
}

fn bench_saturated_multiply_accumulate(c: &mut Criterion) {
	let x = Fixed128::max_value();
	c.bench_function("saturated_multiply_accumulate", |b| b.iter(|| x.saturated_multiply_accumulate(black_box(20u64))));
}

fn bench_checked_mul(c: &mut Criterion) {
	let x = Fixed128::max_value();
	let y = Fixed128::from_integer(20.into());
	c.bench_function("checked_mul_only", |b| b.iter(|| x.checked_mul(black_box(&y))));
}

fn bench_divide(c: &mut Criterion) {
	c.bench_function("divide_rat", |b| b.iter(|| multiply_by_rational(3, i128::max_value() as u128, 16)));

	// c.bench_function("divide_rat", |b| b.iter(|| divide(i128::max_value() as u128, 16, 3)));
}

fn bench_pow(c: &mut Criterion) {
	let x = Fixed128::from_integer(3.into());
	c.bench_function("saturating_pow", |b| b.iter(|| x.saturating_pow(80usize)));
}


criterion_group!{
	name = benches;
	config = Criterion::default();
	targets = bench_addition, bench_subtraction, bench_multiplication, bench_division,
		bench_checked_mul_int, bench_saturated_multiply_accumulate, bench_checked_mul, bench_divide,
		bench_pow
}
criterion_main!(benches);
