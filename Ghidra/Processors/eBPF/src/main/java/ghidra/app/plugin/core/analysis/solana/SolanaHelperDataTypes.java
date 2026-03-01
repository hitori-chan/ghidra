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

import java.io.Closeable;
import java.io.IOException;

import ghidra.app.plugin.core.analysis.TransientProgramProperties;
import ghidra.app.plugin.core.analysis.TransientProgramProperties.SCOPE;
import ghidra.app.util.cparser.C.CParser;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * Provides Solana-specific syscall function signatures.
 * 
 * Creates function definitions for Solana syscalls to improve decompilation quality.
 */
public class SolanaHelperDataTypes implements Closeable {

	private static final String SOLANA_DATATYPE_MGR_PROPERTY_KEY = "SolanaDataTypes";

	/**
	 * Ordered list of Solana syscall signatures. Array index corresponds to syscall ID.
	 * 
	 * References:
	 *   https://github.com/anza-xyz/agave/blob/master/sdk/program/src/syscall.rs
	 */
	//@formatter:off
	private static final String[] solanaSyscallSignatures = new String[] {
		"i64 sol_invoke(const AccountInfo *programs, const u8 *args)",
		"i64 sol_invoke_signed(const AccountInfo *programs, const u8 *args, const u64 *signed_programs_index)",
		"i64 sol_allocate(AccountInfo *account, u64 size)",
		"i64 sol_assign(AccountInfo *account, const Pubkey *owner)",
		"i64 sol_return(const u8 *data, u64 size)",
		"i64 sol_create_account(AccountInfo *dest, u64 lamports, u64 size, const Pubkey *owner)",
		"i64 sol_create_account_with_seed(AccountInfo *dest, const u8 *seed, u64 seed_len, const Pubkey *base, u64 lamports, u64 size, const Pubkey *owner)",
		"i64 sol_close_account(AccountInfo *account, AccountInfo *destination)",
		"i64 sol_invoke_signed_all(const AccountInfo *programs, const u8 *args, const u64 *signed_programs_index, u64 index_len)",
		"i64 sol_memmove(u8 *dest, const u8 *src, u64 len)",
		"i64 sol_keccak256(u8 *dest, const u8 *src, u64 len)",
		"i64 sol_sha256(u8 *dest, const u8 *src, u64 len)",
		"i64 sol_ripemd160(u8 *dest, const u8 *src, u64 len)",
		"i64 sol_secp256k1_recover(u8 *dest, const u8 *hash, u64 hash_len, const u8 *recovery_id, const u8 *signature, u64 signature_len, u64 flag)",
		"i64 sol_secp256r1_verify(u8 *dest, const u8 *hash, u64 hash_len, const u8 *signature, u64 signature_len)",
		"i64 sol_ed25519_verify(u8 *dest, const u8 *message, u64 message_len, const u8 *public_key, const u8 *signature)",
		"i64 sol_ed25519_prehash_verify(u8 *dest, const u8 *prehash, u64 prehash_len, const u8 *public_key, const u8 *signature)"
	};
	//@formatter:on

	private DataTypeManager dtm;
	private FunctionDefinition[] syscallFunctionDefs;

	private SolanaHelperDataTypes(DataTypeManager dtm, FunctionDefinition[] syscallFunctionDefs) {
		this.dtm = dtm;
		this.syscallFunctionDefs = syscallFunctionDefs;
	}

	@Override
	public void close() throws IOException {
		syscallFunctionDefs = null;
		dtm.close();
	}

	FunctionDefinition getSyscallFunctionDef(int id) {
		if (id >= 0 && id < syscallFunctionDefs.length) {
			return syscallFunctionDefs[id];
		}
		return null;
	}

	static synchronized SolanaHelperDataTypes get(Program program, MessageLog log) {

		boolean previouslyParsed =
			TransientProgramProperties.hasProperty(program, SOLANA_DATATYPE_MGR_PROPERTY_KEY);
		SolanaHelperDataTypes instance = TransientProgramProperties.getProperty(program,
			SOLANA_DATATYPE_MGR_PROPERTY_KEY, SCOPE.ANALYSIS_SESSION, SolanaHelperDataTypes.class,
			() -> parseSyscallFunctionDefs(program, log));
		if (instance == null && !previouslyParsed) {
			log.appendMsg("Failed to parse Solana syscall function definitions");
		}
		return instance;
	}

	private static SolanaHelperDataTypes parseSyscallFunctionDefs(Program program, MessageLog log) {

		FunctionDefinition[] syscallFunctionDefs =
			new FunctionDefinition[solanaSyscallSignatures.length];

		boolean success = false;
		DataTypeManager dtm =
			new StandAloneDataTypeManager("Solana", DataOrganizationImpl.getDefaultOrganization());
		int txId = dtm.startTransaction("Parse Solana Types");
		try {

			// Populate typedef dependencies for Solana
			dtm.addDataType(new TypedefDataType("u8", UnsignedCharDataType.dataType), null);
			dtm.addDataType(new TypedefDataType("u16", UnsignedShortDataType.dataType), null);
			dtm.addDataType(new TypedefDataType("u32", UnsignedIntegerDataType.dataType), null);
			dtm.addDataType(new TypedefDataType("u64", UnsignedLongDataType.dataType), null);
			dtm.addDataType(new TypedefDataType("i64", LongDataType.dataType), null);
			
			// Create empty struct definitions for forward references
			StructureDataType accountInfoStruct = new StructureDataType("AccountInfo", 0);
			dtm.addDataType(accountInfoStruct, null);
			
			StructureDataType pubkeyStruct = new StructureDataType("Pubkey", 0);
			dtm.addDataType(pubkeyStruct, null);

			CParser parser = new CParser(dtm, true, null);
			try {
				int id = 0;
				for (String def : solanaSyscallSignatures) {
					syscallFunctionDefs[id++] =
						def != null ? (FunctionDefinition) parser.parse(def + ";") : null;
				}
			}
			catch (ParseException e) {
				Msg.error(SolanaHelperDataTypes.class, "Solana datatype parse error: " +
					e.getMessage() + "\n\n" + parser.getParseMessages());
				if (log != null) {
					log.appendMsg("Parse error: " + e.getMessage());
				}
				return null;
			}

			success = true;
		}
		finally {
			dtm.endTransaction(txId, success);
			if (!success) {
				dtm.close();
			}
		}

		return new SolanaHelperDataTypes(dtm, syscallFunctionDefs);
	}

}
