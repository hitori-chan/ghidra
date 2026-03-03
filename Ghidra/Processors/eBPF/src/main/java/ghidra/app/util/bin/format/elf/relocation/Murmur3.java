/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.util.bin.format.elf.relocation;

/**
 * Murmur3 32-bit hash implementation matching Solana's syscall hashing.
 *
 * Solana eBPF programs use murmur3_32(name.as_bytes(), 0) to map syscall names
 * to numeric IDs. The CALL instruction's immediate field contains this hash.
 *
 * Reference: solana-sbpf/src/ebpf.rs (hash_symbol_name)
 * Reference: agave/platform-tools-sdk/gen-headers/src/main.rs (murmur3_32)
 */
public class Murmur3 {

	private static final int C1 = 0xcc9e2d51;
	private static final int C2 = 0x1b873593;

	/**
	 * Compute murmur3 32-bit hash with seed 0 (Solana convention).
	 *
	 * @param data The byte array to hash (typically UTF-8 encoded syscall name)
	 * @return The 32-bit murmur3 hash as an unsigned value in a long
	 */
	public static long hash(byte[] data) {
		return hash(data, 0);
	}

	/**
	 * Compute murmur3 32-bit hash.
	 *
	 * @param data The byte array to hash
	 * @param seed The hash seed
	 * @return The 32-bit murmur3 hash as an unsigned value in a long
	 */
	public static long hash(byte[] data, int seed) {
		int h = seed;
		int length = data.length;
		int nblocks = length / 4;

		// Body: process 4-byte blocks
		for (int i = 0; i < nblocks; i++) {
			int k = getIntLE(data, i * 4);
			k *= C1;
			k = Integer.rotateLeft(k, 15);
			k *= C2;
			h ^= k;
			h = Integer.rotateLeft(h, 13);
			h = h * 5 + 0xe6546b64;
		}

		// Tail: process remaining bytes
		int tail = nblocks * 4;
		int k = 0;
		switch (length & 3) {
			case 3:
				k ^= (data[tail + 2] & 0xff) << 16;
				// fall through
			case 2:
				k ^= (data[tail + 1] & 0xff) << 8;
				// fall through
			case 1:
				k ^= (data[tail] & 0xff);
				k *= C1;
				k = Integer.rotateLeft(k, 15);
				k *= C2;
				h ^= k;
		}

		// Finalization mix
		h ^= length;
		h ^= (h >>> 16);
		h *= 0x85ebca6b;
		h ^= (h >>> 13);
		h *= 0xc2b2ae35;
		h ^= (h >>> 16);

		// Return as unsigned long
		return h & 0xFFFFFFFFL;
	}

	/**
	 * Read a 32-bit little-endian integer from a byte array.
	 */
	private static int getIntLE(byte[] data, int offset) {
		return (data[offset] & 0xff) |
			((data[offset + 1] & 0xff) << 8) |
			((data[offset + 2] & 0xff) << 16) |
			((data[offset + 3] & 0xff) << 24);
	}
}
