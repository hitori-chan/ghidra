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
package ghidra.app.plugin.core.analysis.solana;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;

/**
 * Solana data structure definitions for improved decompilation.
 *
 * Structures match the authoritative C definitions from agave/platform-tools-sdk/sbf/c/inc/sol/:
 *
 * SolAccountInfo (from entrypoint.h):
 *   SolPubkey *key;       (+0x00, 8 bytes ptr)
 *   uint64_t *lamports;   (+0x08, 8 bytes ptr)
 *   uint64_t data_len;    (+0x10, 8 bytes)
 *   uint8_t *data;        (+0x18, 8 bytes ptr)
 *   SolPubkey *owner;     (+0x20, 8 bytes ptr)
 *   uint64_t rent_epoch;  (+0x28, 8 bytes)
 *   bool is_signer;       (+0x30, 1 byte)
 *   bool is_writable;     (+0x31, 1 byte)
 *   bool executable;      (+0x32, 1 byte)
 *   // Total: 0x38 = 56 bytes (with alignment padding to 8-byte boundary)
 *
 * SolAccountMeta (from cpi.h):
 *   SolPubkey *pubkey;    (+0x00, 8 bytes ptr)
 *   bool is_writable;     (+0x08, 1 byte)
 *   bool is_signer;       (+0x09, 1 byte)
 *
 * SolInstruction (from cpi.h):
 *   SolPubkey *program_id;      (+0x00, 8 bytes ptr)
 *   SolAccountMeta *accounts;   (+0x08, 8 bytes ptr)
 *   uint64_t account_len;       (+0x10, 8 bytes)
 *   uint8_t *data;              (+0x18, 8 bytes ptr)
 *   uint64_t data_len;          (+0x20, 8 bytes)
 */
public class SolanaStructures {

    /**
     * Create Solana-specific data structures in the program's data type manager.
     */
    public static void createSolanaStructures(Program program, MessageLog log) {
        DataTypeManager dtm = program.getDataTypeManager();

        // Check if structures already exist
        if (dtm.getDataType("/SolAccountInfo") != null) {
            return;
        }

        int txId = dtm.startTransaction("Create Solana Structures");
        boolean success = false;
        try {
            // SolPubkey - 32-byte public key (from sol/pubkey.h)
            StructureDataType solPubkey = new StructureDataType("SolPubkey", 0);
            ArrayDataType pubkeyBytes = new ArrayDataType(UnsignedCharDataType.dataType, 32, 1);
            solPubkey.add(pubkeyBytes, "x", "32-byte public key");
            DataType solPubkeyDt = dtm.addDataType(solPubkey, null);

            // SolAccountInfo - account info (from sol/entrypoint.h)
            // AUTHORITATIVE field order: key, lamports, data_len, data, owner, rent_epoch, is_signer, is_writable, executable
            StructureDataType solAccountInfo = new StructureDataType("SolAccountInfo", 0);
            solAccountInfo.add(new PointerDataType(solPubkeyDt), "key", "Public key of the account");
            solAccountInfo.add(new PointerDataType(UnsignedLongLongDataType.dataType), "lamports", "Number of lamports owned by this account");
            solAccountInfo.add(UnsignedLongLongDataType.dataType, "data_len", "Length of data in bytes");
            solAccountInfo.add(new PointerDataType(UnsignedCharDataType.dataType), "data", "On-chain data within this account");
            solAccountInfo.add(new PointerDataType(solPubkeyDt), "owner", "Program that owns this account");
            solAccountInfo.add(UnsignedLongLongDataType.dataType, "rent_epoch", "The epoch at which this account will next owe rent");
            solAccountInfo.add(BooleanDataType.dataType, "is_signer", "Transaction was signed by this account's key?");
            solAccountInfo.add(BooleanDataType.dataType, "is_writable", "Is the account writable?");
            solAccountInfo.add(BooleanDataType.dataType, "executable", "This account's data contains a loaded program");
            dtm.addDataType(solAccountInfo, null);

            // SolAccountMeta - CPI account metadata (from sol/cpi.h)
            StructureDataType solAccountMeta = new StructureDataType("SolAccountMeta", 0);
            solAccountMeta.add(new PointerDataType(solPubkeyDt), "pubkey", "An account's public key");
            solAccountMeta.add(BooleanDataType.dataType, "is_writable", "True if the pubkey can be loaded as read-write");
            solAccountMeta.add(BooleanDataType.dataType, "is_signer", "True if requires Transaction signature matching pubkey");
            DataType solAccountMetaDt = dtm.addDataType(solAccountMeta, null);

            // SolInstruction - CPI instruction (from sol/cpi.h)
            StructureDataType solInstruction = new StructureDataType("SolInstruction", 0);
            solInstruction.add(new PointerDataType(solPubkeyDt), "program_id", "Pubkey of the instruction processor");
            solInstruction.add(new PointerDataType(solAccountMetaDt), "accounts", "Metadata for accounts to pass");
            solInstruction.add(UnsignedLongLongDataType.dataType, "account_len", "Number of SolAccountMetas");
            solInstruction.add(new PointerDataType(UnsignedCharDataType.dataType), "data", "Opaque data passed to instruction processor");
            solInstruction.add(UnsignedLongLongDataType.dataType, "data_len", "Length of the data in bytes");
            dtm.addDataType(solInstruction, null);

            // SolSignerSeed - seed for PDA derivation (from sol/pubkey.h)
            StructureDataType solSignerSeed = new StructureDataType("SolSignerSeed", 0);
            solSignerSeed.add(PointerDataType.dataType, "addr", "Seed bytes");
            solSignerSeed.add(UnsignedLongLongDataType.dataType, "len", "Length of the seed bytes");
            DataType solSignerSeedDt = dtm.addDataType(solSignerSeed, null);

            // SolSignerSeeds - array of seeds (from sol/pubkey.h)
            StructureDataType solSignerSeeds = new StructureDataType("SolSignerSeeds", 0);
            solSignerSeeds.add(new PointerDataType(solSignerSeedDt), "addr", "Array of signer seeds");
            solSignerSeeds.add(UnsignedLongLongDataType.dataType, "len", "Number of seeds");
            dtm.addDataType(solSignerSeeds, null);

            // SolBytes - byte array with length (from sol/types.h)
            StructureDataType solBytesStruct = new StructureDataType("SolBytes", 0);
            solBytesStruct.add(PointerDataType.dataType, "addr", "byte data pointer");
            solBytesStruct.add(UnsignedLongLongDataType.dataType, "len", "number of bytes");
            dtm.addDataType(solBytesStruct, null);

            // SolParameters - entrypoint parameters (from sol/entrypoint.h)
            // This is the C SDK struct - programs access this after deserialization
            StructureDataType solParameters = new StructureDataType("SolParameters", 0);
            solParameters.add(new PointerDataType(dtm.getDataType("/SolAccountInfo")), "ka", "Pointer to array of SolAccountInfo");
            solParameters.add(UnsignedLongLongDataType.dataType, "ka_num", "Number of SolAccountInfo entries");
            solParameters.add(new PointerDataType(UnsignedCharDataType.dataType), "data", "Pointer to instruction data");
            solParameters.add(UnsignedLongLongDataType.dataType, "data_len", "Length of instruction data");
            solParameters.add(new PointerDataType(solPubkeyDt), "program_id", "Program ID of the currently executing program");
            dtm.addDataType(solParameters, null);

            // === Raw serialized account format (ABI v1) ===
            // This matches the binary layout at MM_INPUT_START (0x100000000)
            // From agave/program-runtime/src/serialization.rs: serialize_parameters_for_abiv1()
            // R1 points here at program entry

            // SolSerializedAccount - raw binary layout of a single account in input buffer
            // Fixed-size header (0x58 bytes) followed by variable-length data
            StructureDataType solSerAccount = new StructureDataType("SolSerializedAccount", 0);
            solSerAccount.add(UnsignedCharDataType.dataType, "dup_marker", "0xFF=unique, else index of duplicate");
            solSerAccount.add(UnsignedCharDataType.dataType, "is_signer", "1 if transaction was signed by this key");
            solSerAccount.add(UnsignedCharDataType.dataType, "is_writable", "1 if account is writable");
            solSerAccount.add(UnsignedCharDataType.dataType, "executable", "1 if account contains a program");
            ArrayDataType pad4 = new ArrayDataType(UnsignedCharDataType.dataType, 4, 1);
            solSerAccount.add(pad4, "padding", "Alignment padding to 8 bytes");
            solSerAccount.add(solPubkeyDt, "key", "Account public key (32 bytes)");
            solSerAccount.add(solPubkeyDt, "owner", "Owner program public key (32 bytes)");
            solSerAccount.add(UnsignedLongLongDataType.dataType, "lamports", "Account balance in lamports");
            solSerAccount.add(UnsignedLongLongDataType.dataType, "data_len", "Length of account data");
            // Note: variable-length data follows, then alignment padding, then rent_epoch
            dtm.addDataType(solSerAccount, null);

            // SolSerializedInput - top-level input buffer header at MM_INPUT_START
            StructureDataType solSerInput = new StructureDataType("SolSerializedInput", 0);
            solSerInput.add(UnsignedLongLongDataType.dataType, "num_accounts", "Number of accounts");
            // Note: SolSerializedAccount entries follow (variable-size due to account data)
            dtm.addDataType(solSerInput, null);

            success = true;

            if (log != null) {
                log.appendMsg("Created Solana data structures: SolPubkey, SolAccountInfo, SolAccountMeta, SolInstruction, SolSignerSeed, SolSignerSeeds, SolBytes, SolParameters, SolSerializedAccount, SolSerializedInput");
            }
        } catch (Exception e) {
            if (log != null) {
                log.appendMsg("Error creating Solana structures: " + e.getMessage());
            }
        } finally {
            dtm.endTransaction(txId, success);
        }
    }
}
