SCHEMA_PATH := schemas
SCHEMA_DEST_PATH := generated

schema:
	moleculec --language rust --schema-file ${SCHEMA_PATH}/basic.mol > ${SCHEMA_DEST_PATH}/basic.rs
	moleculec --language rust --schema-file ${SCHEMA_PATH}/transaction_proof.mol > ${SCHEMA_DEST_PATH}/transaction_proof.rs
	cargo fmt
