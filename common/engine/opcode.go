// Copyright (c) 2013-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package engine

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"strings"

	"golang.org/x/crypto/ripemd160"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
)

// An opcode defines the information related to a txscript opcode.  opfunc, if
// present, is the function to call to perform the opcode on the script.  The
// current script is passed in as a slice with the first member being the opcode
// itself.
type opcode struct {
	value  byte
	name   string
	length int
	opfunc func(*opcode, []byte, *Engine) error
}

// opcodeArray holds details about all possible opcodes such as how many bytes
// the opcode and any associated data should take, its human-readable name, and
// the handler function.
var opcodeArray = [256]opcode{
	// Data push opcodes.
	txscript.OP_FALSE:     {txscript.OP_FALSE, "OP_0", 1, opcodeFalse},
	txscript.OP_DATA_1:    {txscript.OP_DATA_1, "OP_DATA_1", 2, opcodePushData},
	txscript.OP_DATA_2:    {txscript.OP_DATA_2, "OP_DATA_2", 3, opcodePushData},
	txscript.OP_DATA_3:    {txscript.OP_DATA_3, "OP_DATA_3", 4, opcodePushData},
	txscript.OP_DATA_4:    {txscript.OP_DATA_4, "OP_DATA_4", 5, opcodePushData},
	txscript.OP_DATA_5:    {txscript.OP_DATA_5, "OP_DATA_5", 6, opcodePushData},
	txscript.OP_DATA_6:    {txscript.OP_DATA_6, "OP_DATA_6", 7, opcodePushData},
	txscript.OP_DATA_7:    {txscript.OP_DATA_7, "OP_DATA_7", 8, opcodePushData},
	txscript.OP_DATA_8:    {txscript.OP_DATA_8, "OP_DATA_8", 9, opcodePushData},
	txscript.OP_DATA_9:    {txscript.OP_DATA_9, "OP_DATA_9", 10, opcodePushData},
	txscript.OP_DATA_10:   {txscript.OP_DATA_10, "OP_DATA_10", 11, opcodePushData},
	txscript.OP_DATA_11:   {txscript.OP_DATA_11, "OP_DATA_11", 12, opcodePushData},
	txscript.OP_DATA_12:   {txscript.OP_DATA_12, "OP_DATA_12", 13, opcodePushData},
	txscript.OP_DATA_13:   {txscript.OP_DATA_13, "OP_DATA_13", 14, opcodePushData},
	txscript.OP_DATA_14:   {txscript.OP_DATA_14, "OP_DATA_14", 15, opcodePushData},
	txscript.OP_DATA_15:   {txscript.OP_DATA_15, "OP_DATA_15", 16, opcodePushData},
	txscript.OP_DATA_16:   {txscript.OP_DATA_16, "OP_DATA_16", 17, opcodePushData},
	txscript.OP_DATA_17:   {txscript.OP_DATA_17, "OP_DATA_17", 18, opcodePushData},
	txscript.OP_DATA_18:   {txscript.OP_DATA_18, "OP_DATA_18", 19, opcodePushData},
	txscript.OP_DATA_19:   {txscript.OP_DATA_19, "OP_DATA_19", 20, opcodePushData},
	txscript.OP_DATA_20:   {txscript.OP_DATA_20, "OP_DATA_20", 21, opcodePushData},
	txscript.OP_DATA_21:   {txscript.OP_DATA_21, "OP_DATA_21", 22, opcodePushData},
	txscript.OP_DATA_22:   {txscript.OP_DATA_22, "OP_DATA_22", 23, opcodePushData},
	txscript.OP_DATA_23:   {txscript.OP_DATA_23, "OP_DATA_23", 24, opcodePushData},
	txscript.OP_DATA_24:   {txscript.OP_DATA_24, "OP_DATA_24", 25, opcodePushData},
	txscript.OP_DATA_25:   {txscript.OP_DATA_25, "OP_DATA_25", 26, opcodePushData},
	txscript.OP_DATA_26:   {txscript.OP_DATA_26, "OP_DATA_26", 27, opcodePushData},
	txscript.OP_DATA_27:   {txscript.OP_DATA_27, "OP_DATA_27", 28, opcodePushData},
	txscript.OP_DATA_28:   {txscript.OP_DATA_28, "OP_DATA_28", 29, opcodePushData},
	txscript.OP_DATA_29:   {txscript.OP_DATA_29, "OP_DATA_29", 30, opcodePushData},
	txscript.OP_DATA_30:   {txscript.OP_DATA_30, "OP_DATA_30", 31, opcodePushData},
	txscript.OP_DATA_31:   {txscript.OP_DATA_31, "OP_DATA_31", 32, opcodePushData},
	txscript.OP_DATA_32:   {txscript.OP_DATA_32, "OP_DATA_32", 33, opcodePushData},
	txscript.OP_DATA_33:   {txscript.OP_DATA_33, "OP_DATA_33", 34, opcodePushData},
	txscript.OP_DATA_34:   {txscript.OP_DATA_34, "OP_DATA_34", 35, opcodePushData},
	txscript.OP_DATA_35:   {txscript.OP_DATA_35, "OP_DATA_35", 36, opcodePushData},
	txscript.OP_DATA_36:   {txscript.OP_DATA_36, "OP_DATA_36", 37, opcodePushData},
	txscript.OP_DATA_37:   {txscript.OP_DATA_37, "OP_DATA_37", 38, opcodePushData},
	txscript.OP_DATA_38:   {txscript.OP_DATA_38, "OP_DATA_38", 39, opcodePushData},
	txscript.OP_DATA_39:   {txscript.OP_DATA_39, "OP_DATA_39", 40, opcodePushData},
	txscript.OP_DATA_40:   {txscript.OP_DATA_40, "OP_DATA_40", 41, opcodePushData},
	txscript.OP_DATA_41:   {txscript.OP_DATA_41, "OP_DATA_41", 42, opcodePushData},
	txscript.OP_DATA_42:   {txscript.OP_DATA_42, "OP_DATA_42", 43, opcodePushData},
	txscript.OP_DATA_43:   {txscript.OP_DATA_43, "OP_DATA_43", 44, opcodePushData},
	txscript.OP_DATA_44:   {txscript.OP_DATA_44, "OP_DATA_44", 45, opcodePushData},
	txscript.OP_DATA_45:   {txscript.OP_DATA_45, "OP_DATA_45", 46, opcodePushData},
	txscript.OP_DATA_46:   {txscript.OP_DATA_46, "OP_DATA_46", 47, opcodePushData},
	txscript.OP_DATA_47:   {txscript.OP_DATA_47, "OP_DATA_47", 48, opcodePushData},
	txscript.OP_DATA_48:   {txscript.OP_DATA_48, "OP_DATA_48", 49, opcodePushData},
	txscript.OP_DATA_49:   {txscript.OP_DATA_49, "OP_DATA_49", 50, opcodePushData},
	txscript.OP_DATA_50:   {txscript.OP_DATA_50, "OP_DATA_50", 51, opcodePushData},
	txscript.OP_DATA_51:   {txscript.OP_DATA_51, "OP_DATA_51", 52, opcodePushData},
	txscript.OP_DATA_52:   {txscript.OP_DATA_52, "OP_DATA_52", 53, opcodePushData},
	txscript.OP_DATA_53:   {txscript.OP_DATA_53, "OP_DATA_53", 54, opcodePushData},
	txscript.OP_DATA_54:   {txscript.OP_DATA_54, "OP_DATA_54", 55, opcodePushData},
	txscript.OP_DATA_55:   {txscript.OP_DATA_55, "OP_DATA_55", 56, opcodePushData},
	txscript.OP_DATA_56:   {txscript.OP_DATA_56, "OP_DATA_56", 57, opcodePushData},
	txscript.OP_DATA_57:   {txscript.OP_DATA_57, "OP_DATA_57", 58, opcodePushData},
	txscript.OP_DATA_58:   {txscript.OP_DATA_58, "OP_DATA_58", 59, opcodePushData},
	txscript.OP_DATA_59:   {txscript.OP_DATA_59, "OP_DATA_59", 60, opcodePushData},
	txscript.OP_DATA_60:   {txscript.OP_DATA_60, "OP_DATA_60", 61, opcodePushData},
	txscript.OP_DATA_61:   {txscript.OP_DATA_61, "OP_DATA_61", 62, opcodePushData},
	txscript.OP_DATA_62:   {txscript.OP_DATA_62, "OP_DATA_62", 63, opcodePushData},
	txscript.OP_DATA_63:   {txscript.OP_DATA_63, "OP_DATA_63", 64, opcodePushData},
	txscript.OP_DATA_64:   {txscript.OP_DATA_64, "OP_DATA_64", 65, opcodePushData},
	txscript.OP_DATA_65:   {txscript.OP_DATA_65, "OP_DATA_65", 66, opcodePushData},
	txscript.OP_DATA_66:   {txscript.OP_DATA_66, "OP_DATA_66", 67, opcodePushData},
	txscript.OP_DATA_67:   {txscript.OP_DATA_67, "OP_DATA_67", 68, opcodePushData},
	txscript.OP_DATA_68:   {txscript.OP_DATA_68, "OP_DATA_68", 69, opcodePushData},
	txscript.OP_DATA_69:   {txscript.OP_DATA_69, "OP_DATA_69", 70, opcodePushData},
	txscript.OP_DATA_70:   {txscript.OP_DATA_70, "OP_DATA_70", 71, opcodePushData},
	txscript.OP_DATA_71:   {txscript.OP_DATA_71, "OP_DATA_71", 72, opcodePushData},
	txscript.OP_DATA_72:   {txscript.OP_DATA_72, "OP_DATA_72", 73, opcodePushData},
	txscript.OP_DATA_73:   {txscript.OP_DATA_73, "OP_DATA_73", 74, opcodePushData},
	txscript.OP_DATA_74:   {txscript.OP_DATA_74, "OP_DATA_74", 75, opcodePushData},
	txscript.OP_DATA_75:   {txscript.OP_DATA_75, "OP_DATA_75", 76, opcodePushData},
	txscript.OP_PUSHDATA1: {txscript.OP_PUSHDATA1, "OP_PUSHDATA1", -1, opcodePushData},
	txscript.OP_PUSHDATA2: {txscript.OP_PUSHDATA2, "OP_PUSHDATA2", -2, opcodePushData},
	txscript.OP_PUSHDATA4: {txscript.OP_PUSHDATA4, "OP_PUSHDATA4", -4, opcodePushData},
	txscript.OP_1NEGATE:   {txscript.OP_1NEGATE, "OP_1NEGATE", 1, opcode1Negate},
	txscript.OP_RESERVED:  {txscript.OP_RESERVED, "OP_RESERVED", 1, opcodeReserved},
	txscript.OP_TRUE:      {txscript.OP_TRUE, "OP_1", 1, opcodeN},
	txscript.OP_2:         {txscript.OP_2, "OP_2", 1, opcodeN},
	txscript.OP_3:         {txscript.OP_3, "OP_3", 1, opcodeN},
	txscript.OP_4:         {txscript.OP_4, "OP_4", 1, opcodeN},
	txscript.OP_5:         {txscript.OP_5, "OP_5", 1, opcodeN},
	txscript.OP_6:         {txscript.OP_6, "OP_6", 1, opcodeN},
	txscript.OP_7:         {txscript.OP_7, "OP_7", 1, opcodeN},
	txscript.OP_8:         {txscript.OP_8, "OP_8", 1, opcodeN},
	txscript.OP_9:         {txscript.OP_9, "OP_9", 1, opcodeN},
	txscript.OP_10:        {txscript.OP_10, "OP_10", 1, opcodeN},
	txscript.OP_11:        {txscript.OP_11, "OP_11", 1, opcodeN},
	txscript.OP_12:        {txscript.OP_12, "OP_12", 1, opcodeN},
	txscript.OP_13:        {txscript.OP_13, "OP_13", 1, opcodeN},
	txscript.OP_14:        {txscript.OP_14, "OP_14", 1, opcodeN},
	txscript.OP_15:        {txscript.OP_15, "OP_15", 1, opcodeN},
	txscript.OP_16:        {txscript.OP_16, "OP_16", 1, opcodeN},

	// Control opcodes.
	txscript.OP_NOP:                 {txscript.OP_NOP, "OP_NOP", 1, opcodeNop},
	txscript.OP_VER:                 {txscript.OP_VER, "OP_VER", 1, opcodeReserved},
	txscript.OP_IF:                  {txscript.OP_IF, "OP_IF", 1, opcodeIf},
	txscript.OP_NOTIF:               {txscript.OP_NOTIF, "OP_NOTIF", 1, opcodeNotIf},
	txscript.OP_VERIF:               {txscript.OP_VERIF, "OP_VERIF", 1, opcodeReserved},
	txscript.OP_VERNOTIF:            {txscript.OP_VERNOTIF, "OP_VERNOTIF", 1, opcodeReserved},
	txscript.OP_ELSE:                {txscript.OP_ELSE, "OP_ELSE", 1, opcodeElse},
	txscript.OP_ENDIF:               {txscript.OP_ENDIF, "OP_ENDIF", 1, opcodeEndif},
	txscript.OP_VERIFY:              {txscript.OP_VERIFY, "OP_VERIFY", 1, opcodeVerify},
	txscript.OP_RETURN:              {txscript.OP_RETURN, "OP_RETURN", 1, opcodeReturn},
	txscript.OP_CHECKLOCKTIMEVERIFY: {txscript.OP_CHECKLOCKTIMEVERIFY, "OP_CHECKLOCKTIMEVERIFY", 1, opcodeSigDisabled},
	txscript.OP_CHECKSEQUENCEVERIFY: {txscript.OP_CHECKSEQUENCEVERIFY, "OP_CHECKSEQUENCEVERIFY", 1, opcodeSigDisabled},

	// Stack opcodes.
	txscript.OP_TOALTSTACK:   {txscript.OP_TOALTSTACK, "OP_TOALTSTACK", 1, opcodeToAltStack},
	txscript.OP_FROMALTSTACK: {txscript.OP_FROMALTSTACK, "OP_FROMALTSTACK", 1, opcodeFromAltStack},
	txscript.OP_2DROP:        {txscript.OP_2DROP, "OP_2DROP", 1, opcode2Drop},
	txscript.OP_2DUP:         {txscript.OP_2DUP, "OP_2DUP", 1, opcode2Dup},
	txscript.OP_3DUP:         {txscript.OP_3DUP, "OP_3DUP", 1, opcode3Dup},
	txscript.OP_2OVER:        {txscript.OP_2OVER, "OP_2OVER", 1, opcode2Over},
	txscript.OP_2ROT:         {txscript.OP_2ROT, "OP_2ROT", 1, opcode2Rot},
	txscript.OP_2SWAP:        {txscript.OP_2SWAP, "OP_2SWAP", 1, opcode2Swap},
	txscript.OP_IFDUP:        {txscript.OP_IFDUP, "OP_IFDUP", 1, opcodeIfDup},
	txscript.OP_DEPTH:        {txscript.OP_DEPTH, "OP_DEPTH", 1, opcodeDepth},
	txscript.OP_DROP:         {txscript.OP_DROP, "OP_DROP", 1, opcodeDrop},
	txscript.OP_DUP:          {txscript.OP_DUP, "OP_DUP", 1, opcodeDup},
	txscript.OP_NIP:          {txscript.OP_NIP, "OP_NIP", 1, opcodeNip},
	txscript.OP_OVER:         {txscript.OP_OVER, "OP_OVER", 1, opcodeOver},
	txscript.OP_PICK:         {txscript.OP_PICK, "OP_PICK", 1, opcodePick},
	txscript.OP_ROLL:         {txscript.OP_ROLL, "OP_ROLL", 1, opcodeRoll},
	txscript.OP_ROT:          {txscript.OP_ROT, "OP_ROT", 1, opcodeRot},
	txscript.OP_SWAP:         {txscript.OP_SWAP, "OP_SWAP", 1, opcodeSwap},
	txscript.OP_TUCK:         {txscript.OP_TUCK, "OP_TUCK", 1, opcodeTuck},

	// Splice opcodes.
	txscript.OP_CAT:    {txscript.OP_CAT, "OP_CAT", 1, opcodeDisabled},
	txscript.OP_SUBSTR: {txscript.OP_SUBSTR, "OP_SUBSTR", 1, opcodeDisabled},
	txscript.OP_LEFT:   {txscript.OP_LEFT, "OP_LEFT", 1, opcodeDisabled},
	txscript.OP_RIGHT:  {txscript.OP_RIGHT, "OP_RIGHT", 1, opcodeDisabled},
	txscript.OP_SIZE:   {txscript.OP_SIZE, "OP_SIZE", 1, opcodeSize},

	// Bitwise logic opcodes.
	txscript.OP_INVERT:      {txscript.OP_INVERT, "OP_INVERT", 1, opcodeDisabled},
	txscript.OP_AND:         {txscript.OP_AND, "OP_AND", 1, opcodeDisabled},
	txscript.OP_OR:          {txscript.OP_OR, "OP_OR", 1, opcodeDisabled},
	txscript.OP_XOR:         {txscript.OP_XOR, "OP_XOR", 1, opcodeDisabled},
	txscript.OP_EQUAL:       {txscript.OP_EQUAL, "OP_EQUAL", 1, opcodeEqual},
	txscript.OP_EQUALVERIFY: {txscript.OP_EQUALVERIFY, "OP_EQUALVERIFY", 1, opcodeEqualVerify},
	txscript.OP_RESERVED1:   {txscript.OP_RESERVED1, "OP_RESERVED1", 1, opcodeReserved},
	txscript.OP_RESERVED2:   {txscript.OP_RESERVED2, "OP_RESERVED2", 1, opcodeReserved},

	// Numeric related opcodes.
	txscript.OP_1ADD:               {txscript.OP_1ADD, "OP_1ADD", 1, opcode1Add},
	txscript.OP_1SUB:               {txscript.OP_1SUB, "OP_1SUB", 1, opcode1Sub},
	txscript.OP_2MUL:               {txscript.OP_2MUL, "OP_2MUL", 1, opcodeDisabled},
	txscript.OP_2DIV:               {txscript.OP_2DIV, "OP_2DIV", 1, opcodeDisabled},
	txscript.OP_NEGATE:             {txscript.OP_NEGATE, "OP_NEGATE", 1, opcodeNegate},
	txscript.OP_ABS:                {txscript.OP_ABS, "OP_ABS", 1, opcodeAbs},
	txscript.OP_NOT:                {txscript.OP_NOT, "OP_NOT", 1, opcodeNot},
	txscript.OP_0NOTEQUAL:          {txscript.OP_0NOTEQUAL, "OP_0NOTEQUAL", 1, opcode0NotEqual},
	txscript.OP_ADD:                {txscript.OP_ADD, "OP_ADD", 1, opcodeAdd},
	txscript.OP_SUB:                {txscript.OP_SUB, "OP_SUB", 1, opcodeSub},
	txscript.OP_MUL:                {txscript.OP_MUL, "OP_MUL", 1, opcodeDisabled},
	txscript.OP_DIV:                {txscript.OP_DIV, "OP_DIV", 1, opcodeDisabled},
	txscript.OP_MOD:                {txscript.OP_MOD, "OP_MOD", 1, opcodeDisabled},
	txscript.OP_LSHIFT:             {txscript.OP_LSHIFT, "OP_LSHIFT", 1, opcodeDisabled},
	txscript.OP_RSHIFT:             {txscript.OP_RSHIFT, "OP_RSHIFT", 1, opcodeDisabled},
	txscript.OP_BOOLAND:            {txscript.OP_BOOLAND, "OP_BOOLAND", 1, opcodeBoolAnd},
	txscript.OP_BOOLOR:             {txscript.OP_BOOLOR, "OP_BOOLOR", 1, opcodeBoolOr},
	txscript.OP_NUMEQUAL:           {txscript.OP_NUMEQUAL, "OP_NUMEQUAL", 1, opcodeNumEqual},
	txscript.OP_NUMEQUALVERIFY:     {txscript.OP_NUMEQUALVERIFY, "OP_NUMEQUALVERIFY", 1, opcodeNumEqualVerify},
	txscript.OP_NUMNOTEQUAL:        {txscript.OP_NUMNOTEQUAL, "OP_NUMNOTEQUAL", 1, opcodeNumNotEqual},
	txscript.OP_LESSTHAN:           {txscript.OP_LESSTHAN, "OP_LESSTHAN", 1, opcodeLessThan},
	txscript.OP_GREATERTHAN:        {txscript.OP_GREATERTHAN, "OP_GREATERTHAN", 1, opcodeGreaterThan},
	txscript.OP_LESSTHANOREQUAL:    {txscript.OP_LESSTHANOREQUAL, "OP_LESSTHANOREQUAL", 1, opcodeLessThanOrEqual},
	txscript.OP_GREATERTHANOREQUAL: {txscript.OP_GREATERTHANOREQUAL, "OP_GREATERTHANOREQUAL", 1, opcodeGreaterThanOrEqual},
	txscript.OP_MIN:                {txscript.OP_MIN, "OP_MIN", 1, opcodeMin},
	txscript.OP_MAX:                {txscript.OP_MAX, "OP_MAX", 1, opcodeMax},
	txscript.OP_WITHIN:             {txscript.OP_WITHIN, "OP_WITHIN", 1, opcodeWithin},

	// Crypto opcodes.
	txscript.OP_RIPEMD160:           {txscript.OP_RIPEMD160, "OP_RIPEMD160", 1, opcodeRipemd160},
	txscript.OP_SHA1:                {txscript.OP_SHA1, "OP_SHA1", 1, opcodeSha1},
	txscript.OP_SHA256:              {txscript.OP_SHA256, "OP_SHA256", 1, opcodeSha256},
	txscript.OP_HASH160:             {txscript.OP_HASH160, "OP_HASH160", 1, opcodeHash160},
	txscript.OP_HASH256:             {txscript.OP_HASH256, "OP_HASH256", 1, opcodeHash256},
	txscript.OP_CODESEPARATOR:       {txscript.OP_CODESEPARATOR, "OP_CODESEPARATOR", 1, opcodeSigDisabled},
	txscript.OP_CHECKSIG:            {txscript.OP_CHECKSIG, "OP_CHECKSIG", 1, opcodeSigDisabled},
	txscript.OP_CHECKSIGVERIFY:      {txscript.OP_CHECKSIGVERIFY, "OP_CHECKSIGVERIFY", 1, opcodeSigDisabled},
	txscript.OP_CHECKMULTISIG:       {txscript.OP_CHECKMULTISIG, "OP_CHECKMULTISIG", 1, opcodeSigDisabled},
	txscript.OP_CHECKMULTISIGVERIFY: {txscript.OP_CHECKMULTISIGVERIFY, "OP_CHECKMULTISIGVERIFY", 1, opcodeSigDisabled},
	txscript.OP_CHECKSIGADD:         {txscript.OP_CHECKSIGADD, "OP_CHECKSIGADD", 1, opcodeSigDisabled},

	// Reserved opcodes.
	txscript.OP_NOP1:  {txscript.OP_NOP1, "OP_NOP1", 1, opcodeNop},
	txscript.OP_NOP4:  {txscript.OP_NOP4, "OP_NOP4", 1, opcodeNop},
	txscript.OP_NOP5:  {txscript.OP_NOP5, "OP_NOP5", 1, opcodeNop},
	txscript.OP_NOP6:  {txscript.OP_NOP6, "OP_NOP6", 1, opcodeNop},
	txscript.OP_NOP7:  {txscript.OP_NOP7, "OP_NOP7", 1, opcodeNop},
	txscript.OP_NOP8:  {txscript.OP_NOP8, "OP_NOP8", 1, opcodeNop},
	txscript.OP_NOP9:  {txscript.OP_NOP9, "OP_NOP9", 1, opcodeNop},
	txscript.OP_NOP10: {txscript.OP_NOP10, "OP_NOP10", 1, opcodeNop},

	// Undefined opcodes.
	txscript.OP_UNKNOWN187: {txscript.OP_UNKNOWN187, "OP_UNKNOWN187", 1, opcodeInvalid},
	txscript.OP_UNKNOWN188: {txscript.OP_UNKNOWN188, "OP_UNKNOWN188", 1, opcodeInvalid},
	txscript.OP_UNKNOWN189: {txscript.OP_UNKNOWN189, "OP_UNKNOWN189", 1, opcodeInvalid},
	txscript.OP_UNKNOWN190: {txscript.OP_UNKNOWN190, "OP_UNKNOWN190", 1, opcodeInvalid},
	txscript.OP_UNKNOWN191: {txscript.OP_UNKNOWN191, "OP_UNKNOWN191", 1, opcodeInvalid},
	txscript.OP_UNKNOWN192: {txscript.OP_UNKNOWN192, "OP_UNKNOWN192", 1, opcodeInvalid},
	txscript.OP_UNKNOWN193: {txscript.OP_UNKNOWN193, "OP_UNKNOWN193", 1, opcodeInvalid},
	txscript.OP_UNKNOWN194: {txscript.OP_UNKNOWN194, "OP_UNKNOWN194", 1, opcodeInvalid},
	txscript.OP_UNKNOWN195: {txscript.OP_UNKNOWN195, "OP_UNKNOWN195", 1, opcodeInvalid},
	txscript.OP_UNKNOWN196: {txscript.OP_UNKNOWN196, "OP_UNKNOWN196", 1, opcodeInvalid},
	txscript.OP_UNKNOWN197: {txscript.OP_UNKNOWN197, "OP_UNKNOWN197", 1, opcodeInvalid},
	txscript.OP_UNKNOWN198: {txscript.OP_UNKNOWN198, "OP_UNKNOWN198", 1, opcodeInvalid},
	txscript.OP_UNKNOWN199: {txscript.OP_UNKNOWN199, "OP_UNKNOWN199", 1, opcodeInvalid},
	txscript.OP_UNKNOWN200: {txscript.OP_UNKNOWN200, "OP_UNKNOWN200", 1, opcodeInvalid},
	txscript.OP_UNKNOWN201: {txscript.OP_UNKNOWN201, "OP_UNKNOWN201", 1, opcodeInvalid},
	txscript.OP_UNKNOWN202: {txscript.OP_UNKNOWN202, "OP_UNKNOWN202", 1, opcodeInvalid},
	txscript.OP_UNKNOWN203: {txscript.OP_UNKNOWN203, "OP_UNKNOWN203", 1, opcodeInvalid},
	txscript.OP_UNKNOWN204: {txscript.OP_UNKNOWN204, "OP_UNKNOWN204", 1, opcodeInvalid},
	txscript.OP_UNKNOWN205: {txscript.OP_UNKNOWN205, "OP_UNKNOWN205", 1, opcodeInvalid},
	txscript.OP_UNKNOWN206: {txscript.OP_UNKNOWN206, "OP_UNKNOWN206", 1, opcodeInvalid},
	txscript.OP_UNKNOWN207: {txscript.OP_UNKNOWN207, "OP_UNKNOWN207", 1, opcodeInvalid},
	txscript.OP_UNKNOWN208: {txscript.OP_UNKNOWN208, "OP_UNKNOWN208", 1, opcodeInvalid},
	txscript.OP_UNKNOWN209: {txscript.OP_UNKNOWN209, "OP_UNKNOWN209", 1, opcodeInvalid},
	txscript.OP_UNKNOWN210: {txscript.OP_UNKNOWN210, "OP_UNKNOWN210", 1, opcodeInvalid},
	txscript.OP_UNKNOWN211: {txscript.OP_UNKNOWN211, "OP_UNKNOWN211", 1, opcodeInvalid},
	txscript.OP_UNKNOWN212: {txscript.OP_UNKNOWN212, "OP_UNKNOWN212", 1, opcodeInvalid},
	txscript.OP_UNKNOWN213: {txscript.OP_UNKNOWN213, "OP_UNKNOWN213", 1, opcodeInvalid},
	txscript.OP_UNKNOWN214: {txscript.OP_UNKNOWN214, "OP_UNKNOWN214", 1, opcodeInvalid},
	txscript.OP_UNKNOWN215: {txscript.OP_UNKNOWN215, "OP_UNKNOWN215", 1, opcodeInvalid},
	txscript.OP_UNKNOWN216: {txscript.OP_UNKNOWN216, "OP_UNKNOWN216", 1, opcodeInvalid},
	txscript.OP_UNKNOWN217: {txscript.OP_UNKNOWN217, "OP_UNKNOWN217", 1, opcodeInvalid},
	txscript.OP_UNKNOWN218: {txscript.OP_UNKNOWN218, "OP_UNKNOWN218", 1, opcodeInvalid},
	txscript.OP_UNKNOWN219: {txscript.OP_UNKNOWN219, "OP_UNKNOWN219", 1, opcodeInvalid},
	txscript.OP_UNKNOWN220: {txscript.OP_UNKNOWN220, "OP_UNKNOWN220", 1, opcodeInvalid},
	txscript.OP_UNKNOWN221: {txscript.OP_UNKNOWN221, "OP_UNKNOWN221", 1, opcodeInvalid},
	txscript.OP_UNKNOWN222: {txscript.OP_UNKNOWN222, "OP_UNKNOWN222", 1, opcodeInvalid},
	txscript.OP_UNKNOWN223: {txscript.OP_UNKNOWN223, "OP_UNKNOWN223", 1, opcodeInvalid},
	txscript.OP_UNKNOWN224: {txscript.OP_UNKNOWN224, "OP_UNKNOWN224", 1, opcodeInvalid},
	txscript.OP_UNKNOWN225: {txscript.OP_UNKNOWN225, "OP_UNKNOWN225", 1, opcodeInvalid},
	txscript.OP_UNKNOWN226: {txscript.OP_UNKNOWN226, "OP_UNKNOWN226", 1, opcodeInvalid},
	txscript.OP_UNKNOWN227: {txscript.OP_UNKNOWN227, "OP_UNKNOWN227", 1, opcodeInvalid},
	txscript.OP_UNKNOWN228: {txscript.OP_UNKNOWN228, "OP_UNKNOWN228", 1, opcodeInvalid},
	txscript.OP_UNKNOWN229: {txscript.OP_UNKNOWN229, "OP_UNKNOWN229", 1, opcodeInvalid},
	txscript.OP_UNKNOWN230: {txscript.OP_UNKNOWN230, "OP_UNKNOWN230", 1, opcodeInvalid},
	txscript.OP_UNKNOWN231: {txscript.OP_UNKNOWN231, "OP_UNKNOWN231", 1, opcodeInvalid},
	txscript.OP_UNKNOWN232: {txscript.OP_UNKNOWN232, "OP_UNKNOWN232", 1, opcodeInvalid},
	txscript.OP_UNKNOWN233: {txscript.OP_UNKNOWN233, "OP_UNKNOWN233", 1, opcodeInvalid},
	txscript.OP_UNKNOWN234: {txscript.OP_UNKNOWN234, "OP_UNKNOWN234", 1, opcodeInvalid},
	txscript.OP_UNKNOWN235: {txscript.OP_UNKNOWN235, "OP_UNKNOWN235", 1, opcodeInvalid},
	txscript.OP_UNKNOWN236: {txscript.OP_UNKNOWN236, "OP_UNKNOWN236", 1, opcodeInvalid},
	txscript.OP_UNKNOWN237: {txscript.OP_UNKNOWN237, "OP_UNKNOWN237", 1, opcodeInvalid},
	txscript.OP_UNKNOWN238: {txscript.OP_UNKNOWN238, "OP_UNKNOWN238", 1, opcodeInvalid},
	txscript.OP_UNKNOWN239: {txscript.OP_UNKNOWN239, "OP_UNKNOWN239", 1, opcodeInvalid},
	txscript.OP_UNKNOWN240: {txscript.OP_UNKNOWN240, "OP_UNKNOWN240", 1, opcodeInvalid},
	txscript.OP_UNKNOWN241: {txscript.OP_UNKNOWN241, "OP_UNKNOWN241", 1, opcodeInvalid},
	txscript.OP_UNKNOWN242: {txscript.OP_UNKNOWN242, "OP_UNKNOWN242", 1, opcodeInvalid},
	txscript.OP_UNKNOWN243: {txscript.OP_UNKNOWN243, "OP_UNKNOWN243", 1, opcodeInvalid},
	txscript.OP_UNKNOWN244: {txscript.OP_UNKNOWN244, "OP_UNKNOWN244", 1, opcodeInvalid},
	txscript.OP_UNKNOWN245: {txscript.OP_UNKNOWN245, "OP_UNKNOWN245", 1, opcodeInvalid},
	txscript.OP_UNKNOWN246: {txscript.OP_UNKNOWN246, "OP_UNKNOWN246", 1, opcodeInvalid},
	txscript.OP_UNKNOWN247: {txscript.OP_UNKNOWN247, "OP_UNKNOWN247", 1, opcodeInvalid},
	txscript.OP_UNKNOWN248: {txscript.OP_UNKNOWN248, "OP_UNKNOWN248", 1, opcodeInvalid},
	txscript.OP_UNKNOWN249: {txscript.OP_UNKNOWN249, "OP_UNKNOWN249", 1, opcodeInvalid},

	// Bitcoin Core internal use opcode.  Defined here for completeness.
	txscript.OP_SMALLINTEGER: {txscript.OP_SMALLINTEGER, "OP_SMALLINTEGER", 1, opcodeInvalid},
	txscript.OP_PUBKEYS:      {txscript.OP_PUBKEYS, "OP_PUBKEYS", 1, opcodeInvalid},
	txscript.OP_UNKNOWN252:   {txscript.OP_UNKNOWN252, "OP_UNKNOWN252", 1, opcodeInvalid},
	txscript.OP_PUBKEYHASH:   {txscript.OP_PUBKEYHASH, "OP_PUBKEYHASH", 1, opcodeInvalid},
	txscript.OP_PUBKEY:       {txscript.OP_PUBKEY, "OP_PUBKEY", 1, opcodeInvalid},

	txscript.OP_INVALIDOPCODE: {txscript.OP_INVALIDOPCODE, "OP_INVALIDOPCODE", 1, opcodeInvalid},
}

// opcodeOnelineRepls defines opcode names which are replaced when doing a
// one-line disassembly.  This is done to match the output of the reference
// implementation while not changing the opcode names in the nicer full
// disassembly.
var opcodeOnelineRepls = map[string]string{
	"OP_1NEGATE": "-1",
	"OP_0":       "0",
	"OP_1":       "1",
	"OP_2":       "2",
	"OP_3":       "3",
	"OP_4":       "4",
	"OP_5":       "5",
	"OP_6":       "6",
	"OP_7":       "7",
	"OP_8":       "8",
	"OP_9":       "9",
	"OP_10":      "10",
	"OP_11":      "11",
	"OP_12":      "12",
	"OP_13":      "13",
	"OP_14":      "14",
	"OP_15":      "15",
	"OP_16":      "16",
}

// disasmOpcode writes a human-readable disassembly of the provided opcode and
// data into the provided buffer.  The compact flag indicates the disassembly
// should print a more compact representation of data-carrying and small integer
// opcodes.  For example, OP_0 through OP_16 are replaced with the numeric value
// and data pushes are printed as only the hex representation of the data as
// opposed to including the opcode that specifies the amount of data to push as
// well.
func disasmOpcode(buf *strings.Builder, op *opcode, data []byte, compact bool) {
	// Replace opcode which represent values (e.g. OP_0 through OP_16 and
	// OP_1NEGATE) with the raw value when performing a compact disassembly.
	opcodeName := op.name
	if compact {
		if replName, ok := opcodeOnelineRepls[opcodeName]; ok {
			opcodeName = replName
		}

		// Either write the human-readable opcode or the parsed data in hex for
		// data-carrying opcodes.
		switch {
		case op.length == 1:
			buf.WriteString(opcodeName)

		default:
			buf.WriteString(hex.EncodeToString(data))
		}

		return
	}

	buf.WriteString(opcodeName)

	switch op.length {
	// Only write the opcode name for non-data push opcodes.
	case 1:
		return

	// Add length for the OP_PUSHDATA# opcodes.
	case -1:
		buf.WriteString(fmt.Sprintf(" 0x%02x", len(data)))
	case -2:
		buf.WriteString(fmt.Sprintf(" 0x%04x", len(data)))
	case -4:
		buf.WriteString(fmt.Sprintf(" 0x%08x", len(data)))
	}

	buf.WriteString(fmt.Sprintf(" 0x%02x", data))
}

// *******************************************
// Opcode implementation functions start here.
// *******************************************

// opcodeDisabled is a common handler for disabled opcodes.  It returns an
// appropriate error indicating the opcode is disabled.  While it would
// ordinarily make more sense to detect if the script contains any disabled
// opcodes before executing in an initial parse step, the consensus rules
// dictate the script doesn't fail until the program counter passes over a
// disabled opcode (even when they appear in a branch that is not executed).
func opcodeDisabled(op *opcode, data []byte, vm *Engine) error {
	str := fmt.Sprintf("attempt to execute disabled opcode %s", op.name)
	return scriptError(txscript.ErrDisabledOpcode, str)
}

// opcodeReserved is a common handler for all reserved opcodes.  It returns an
// appropriate error indicating the opcode is reserved.
func opcodeReserved(op *opcode, data []byte, vm *Engine) error {
	str := fmt.Sprintf("attempt to execute reserved opcode %s", op.name)
	return scriptError(txscript.ErrReservedOpcode, str)
}

// opcodeInvalid is a common handler for all invalid opcodes.  It returns an
// appropriate error indicating the opcode is invalid.
func opcodeInvalid(op *opcode, data []byte, vm *Engine) error {
	str := fmt.Sprintf("attempt to execute invalid opcode %s", op.name)
	return scriptError(txscript.ErrReservedOpcode, str)
}

// opcodeFalse pushes an empty array to the data stack to represent false.  Note
// that 0, when encoded as a number according to the numeric encoding consensus
// rules, is an empty array.
func opcodeFalse(op *opcode, data []byte, vm *Engine) error {
	vm.dstack.PushByteArray(nil)
	return nil
}

// opcodePushData is a common handler for the vast majority of opcodes that push
// raw data (bytes) to the data stack.
func opcodePushData(op *opcode, data []byte, vm *Engine) error {
	vm.dstack.PushByteArray(data)
	return nil
}

// opcode1Negate pushes -1, encoded as a number, to the data stack.
func opcode1Negate(op *opcode, data []byte, vm *Engine) error {
	vm.dstack.PushInt(scriptNum(-1))
	return nil
}

// opcodeN is a common handler for the small integer data push opcodes.  It
// pushes the numeric value the opcode represents (which will be from 1 to 16)
// onto the data stack.
func opcodeN(op *opcode, data []byte, vm *Engine) error {
	// The opcodes are all defined consecutively, so the numeric value is
	// the difference.
	vm.dstack.PushInt(scriptNum((op.value - (txscript.OP_1 - 1))))
	return nil
}

// opcodeNop is a common handler for the NOP family of opcodes.  As the name
// implies it generally does nothing, however, it will return an error when
// the flag to discourage use of NOPs is set for select opcodes.
func opcodeNop(op *opcode, data []byte, vm *Engine) error {
	switch op.value {
	case txscript.OP_NOP1, txscript.OP_NOP4, txscript.OP_NOP5,
		txscript.OP_NOP6, txscript.OP_NOP7, txscript.OP_NOP8, txscript.OP_NOP9, txscript.OP_NOP10:

		if vm.hasFlag(ScriptDiscourageUpgradableNops) {
			str := fmt.Sprintf("%v reserved for soft-fork "+
				"upgrades", op.name)
			return scriptError(txscript.ErrDiscourageUpgradableNOPs, str)
		}
	}
	return nil
}

// popIfBool enforces the "minimal if" policy during script execution if the
// particular flag is set.  If so, in order to eliminate an additional source
// of nuisance malleability, post-segwit for version 0 witness programs, we now
// require the following: for OP_IF and OP_NOT_IF, the top stack item MUST
// either be an empty byte slice, or [0x01]. Otherwise, the item at the top of
// the stack will be popped and interpreted as a boolean.
func popIfBool(vm *Engine) (bool, error) {
	// When not in witness execution mode, not executing a v0 witness
	// program, or not doing tapscript execution, or the minimal if flag
	// isn't set pop the top stack item as a normal bool.
	switch {
	// Minimal if is always on for taproot execution.
	case vm.isWitnessVersionActive(TaprootWitnessVersion):
		break

	// If this isn't the base segwit version, then we'll coerce the stack
	// element as a bool as normal.
	case !vm.isWitnessVersionActive(BaseSegwitWitnessVersion):
		fallthrough

	// If the minimal if flag isn't set, then we don't need any extra
	// checks here.
	case !vm.hasFlag(ScriptVerifyMinimalIf):
		return vm.dstack.PopBool()
	}

	// At this point, a v0 or v1 witness program is being executed and the
	// minimal if flag is set, so enforce additional constraints on the top
	// stack item.
	so, err := vm.dstack.PopByteArray()
	if err != nil {
		return false, err
	}

	// The top element MUST have a length of at least one.
	if len(so) > 1 {
		str := fmt.Sprintf("minimal if is active, top element MUST "+
			"have a length of at least, instead length is %v",
			len(so))
		return false, scriptError(txscript.ErrMinimalIf, str)
	}

	// Additionally, if the length is one, then the value MUST be 0x01.
	if len(so) == 1 && so[0] != 0x01 {
		str := fmt.Sprintf("minimal if is active, top stack item MUST "+
			"be an empty byte array or 0x01, is instead: %v",
			so[0])
		return false, scriptError(txscript.ErrMinimalIf, str)
	}

	return asBool(so), nil
}

// opcodeIf treats the top item on the data stack as a boolean and removes it.
//
// An appropriate entry is added to the conditional stack depending on whether
// the boolean is true and whether this if is on an executing branch in order
// to allow proper execution of further opcodes depending on the conditional
// logic.  When the boolean is true, the first branch will be executed (unless
// this opcode is nested in a non-executed branch).
//
// <expression> if [statements] [else [statements]] endif
//
// Note that, unlike for all non-conditional opcodes, this is executed even when
// it is on a non-executing branch so proper nesting is maintained.
//
// Data stack transformation: [... bool] -> [...]
// Conditional stack transformation: [...] -> [... OpCondValue]
func opcodeIf(op *opcode, data []byte, vm *Engine) error {
	condVal := txscript.OpCondFalse
	if vm.isBranchExecuting() {
		ok, err := popIfBool(vm)
		if err != nil {
			return err
		}

		if ok {
			condVal = txscript.OpCondTrue
		}
	} else {
		condVal = txscript.OpCondSkip
	}
	vm.condStack = append(vm.condStack, condVal)
	return nil
}

// opcodeNotIf treats the top item on the data stack as a boolean and removes
// it.
//
// An appropriate entry is added to the conditional stack depending on whether
// the boolean is true and whether this if is on an executing branch in order
// to allow proper execution of further opcodes depending on the conditional
// logic.  When the boolean is false, the first branch will be executed (unless
// this opcode is nested in a non-executed branch).
//
// <expression> notif [statements] [else [statements]] endif
//
// Note that, unlike for all non-conditional opcodes, this is executed even when
// it is on a non-executing branch so proper nesting is maintained.
//
// Data stack transformation: [... bool] -> [...]
// Conditional stack transformation: [...] -> [... OpCondValue]
func opcodeNotIf(op *opcode, data []byte, vm *Engine) error {
	condVal := txscript.OpCondFalse
	if vm.isBranchExecuting() {
		ok, err := popIfBool(vm)
		if err != nil {
			return err
		}

		if !ok {
			condVal = txscript.OpCondTrue
		}
	} else {
		condVal = txscript.OpCondSkip
	}
	vm.condStack = append(vm.condStack, condVal)
	return nil
}

// opcodeElse inverts conditional execution for other half of if/else/endif.
//
// An error is returned if there has not already been a matching OP_IF.
//
// Conditional stack transformation: [... OpCondValue] -> [... !OpCondValue]
func opcodeElse(op *opcode, data []byte, vm *Engine) error {
	if len(vm.condStack) == 0 {
		str := fmt.Sprintf("encountered opcode %s with no matching "+
			"opcode to begin conditional execution", op.name)
		return scriptError(txscript.ErrUnbalancedConditional, str)
	}

	conditionalIdx := len(vm.condStack) - 1
	switch vm.condStack[conditionalIdx] {
	case txscript.OpCondTrue:
		vm.condStack[conditionalIdx] = txscript.OpCondFalse
	case txscript.OpCondFalse:
		vm.condStack[conditionalIdx] = txscript.OpCondTrue
	case txscript.OpCondSkip:
		// Value doesn't change in skip since it indicates this opcode
		// is nested in a non-executed branch.
	}
	return nil
}

// opcodeEndif terminates a conditional block, removing the value from the
// conditional execution stack.
//
// An error is returned if there has not already been a matching OP_IF.
//
// Conditional stack transformation: [... OpCondValue] -> [...]
func opcodeEndif(op *opcode, data []byte, vm *Engine) error {
	if len(vm.condStack) == 0 {
		str := fmt.Sprintf("encountered opcode %s with no matching "+
			"opcode to begin conditional execution", op.name)
		return scriptError(txscript.ErrUnbalancedConditional, str)
	}

	vm.condStack = vm.condStack[:len(vm.condStack)-1]
	return nil
}

// abstractVerify examines the top item on the data stack as a boolean value and
// verifies it evaluates to true.  An error is returned either when there is no
// item on the stack or when that item evaluates to false.  In the latter case
// where the verification fails specifically due to the top item evaluating
// to false, the returned error will use the passed error code.
func abstractVerify(op *opcode, vm *Engine, c txscript.ErrorCode) error {
	verified, err := vm.dstack.PopBool()
	if err != nil {
		return err
	}

	if !verified {
		str := fmt.Sprintf("%s failed", op.name)
		return scriptError(c, str)
	}
	return nil
}

// opcodeVerify examines the top item on the data stack as a boolean value and
// verifies it evaluates to true.  An error is returned if it does not.
func opcodeVerify(op *opcode, data []byte, vm *Engine) error {
	return abstractVerify(op, vm, txscript.ErrVerify)
}

// opcodeReturn returns an appropriate error since it is always an error to
// return early from a script.
func opcodeReturn(op *opcode, data []byte, vm *Engine) error {
	return scriptError(txscript.ErrEarlyReturn, "script returned early")
}

// opcodeToAltStack removes the top item from the main data stack and pushes it
// onto the alternate data stack.
//
// Main data stack transformation: [... x1 x2 x3] -> [... x1 x2]
// Alt data stack transformation:  [... y1 y2 y3] -> [... y1 y2 y3 x3]
func opcodeToAltStack(op *opcode, data []byte, vm *Engine) error {
	so, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}
	vm.astack.PushByteArray(so)

	return nil
}

// opcodeFromAltStack removes the top item from the alternate data stack and
// pushes it onto the main data stack.
//
// Main data stack transformation: [... x1 x2 x3] -> [... x1 x2 x3 y3]
// Alt data stack transformation:  [... y1 y2 y3] -> [... y1 y2]
func opcodeFromAltStack(op *opcode, data []byte, vm *Engine) error {
	so, err := vm.astack.PopByteArray()
	if err != nil {
		return err
	}
	vm.dstack.PushByteArray(so)

	return nil
}

// opcode2Drop removes the top 2 items from the data stack.
//
// Stack transformation: [... x1 x2 x3] -> [... x1]
func opcode2Drop(op *opcode, data []byte, vm *Engine) error {
	return vm.dstack.DropN(2)
}

// opcode2Dup duplicates the top 2 items on the data stack.
//
// Stack transformation: [... x1 x2 x3] -> [... x1 x2 x3 x2 x3]
func opcode2Dup(op *opcode, data []byte, vm *Engine) error {
	return vm.dstack.DupN(2)
}

// opcode3Dup duplicates the top 3 items on the data stack.
//
// Stack transformation: [... x1 x2 x3] -> [... x1 x2 x3 x1 x2 x3]
func opcode3Dup(op *opcode, data []byte, vm *Engine) error {
	return vm.dstack.DupN(3)
}

// opcode2Over duplicates the 2 items before the top 2 items on the data stack.
//
// Stack transformation: [... x1 x2 x3 x4] -> [... x1 x2 x3 x4 x1 x2]
func opcode2Over(op *opcode, data []byte, vm *Engine) error {
	return vm.dstack.OverN(2)
}

// opcode2Rot rotates the top 6 items on the data stack to the left twice.
//
// Stack transformation: [... x1 x2 x3 x4 x5 x6] -> [... x3 x4 x5 x6 x1 x2]
func opcode2Rot(op *opcode, data []byte, vm *Engine) error {
	return vm.dstack.RotN(2)
}

// opcode2Swap swaps the top 2 items on the data stack with the 2 that come
// before them.
//
// Stack transformation: [... x1 x2 x3 x4] -> [... x3 x4 x1 x2]
func opcode2Swap(op *opcode, data []byte, vm *Engine) error {
	return vm.dstack.SwapN(2)
}

// opcodeIfDup duplicates the top item of the stack if it is not zero.
//
// Stack transformation (x1==0): [... x1] -> [... x1]
// Stack transformation (x1!=0): [... x1] -> [... x1 x1]
func opcodeIfDup(op *opcode, data []byte, vm *Engine) error {
	so, err := vm.dstack.PeekByteArray(0)
	if err != nil {
		return err
	}

	// Push copy of data iff it isn't zero
	if asBool(so) {
		vm.dstack.PushByteArray(so)
	}

	return nil
}

// opcodeDepth pushes the depth of the data stack prior to executing this
// opcode, encoded as a number, onto the data stack.
//
// Stack transformation: [...] -> [... <num of items on the stack>]
// Example with 2 items: [x1 x2] -> [x1 x2 2]
// Example with 3 items: [x1 x2 x3] -> [x1 x2 x3 3]
func opcodeDepth(op *opcode, data []byte, vm *Engine) error {
	vm.dstack.PushInt(scriptNum(vm.dstack.Depth()))
	return nil
}

// opcodeDrop removes the top item from the data stack.
//
// Stack transformation: [... x1 x2 x3] -> [... x1 x2]
func opcodeDrop(op *opcode, data []byte, vm *Engine) error {
	return vm.dstack.DropN(1)
}

// opcodeDup duplicates the top item on the data stack.
//
// Stack transformation: [... x1 x2 x3] -> [... x1 x2 x3 x3]
func opcodeDup(op *opcode, data []byte, vm *Engine) error {
	return vm.dstack.DupN(1)
}

// opcodeNip removes the item before the top item on the data stack.
//
// Stack transformation: [... x1 x2 x3] -> [... x1 x3]
func opcodeNip(op *opcode, data []byte, vm *Engine) error {
	return vm.dstack.NipN(1)
}

// opcodeOver duplicates the item before the top item on the data stack.
//
// Stack transformation: [... x1 x2 x3] -> [... x1 x2 x3 x2]
func opcodeOver(op *opcode, data []byte, vm *Engine) error {
	return vm.dstack.OverN(1)
}

// opcodePick treats the top item on the data stack as an integer and duplicates
// the item on the stack that number of items back to the top.
//
// Stack transformation: [xn ... x2 x1 x0 n] -> [xn ... x2 x1 x0 xn]
// Example with n=1: [x2 x1 x0 1] -> [x2 x1 x0 x1]
// Example with n=2: [x2 x1 x0 2] -> [x2 x1 x0 x2]
func opcodePick(op *opcode, data []byte, vm *Engine) error {
	val, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	return vm.dstack.PickN(val.Int32())
}

// opcodeRoll treats the top item on the data stack as an integer and moves
// the item on the stack that number of items back to the top.
//
// Stack transformation: [xn ... x2 x1 x0 n] -> [... x2 x1 x0 xn]
// Example with n=1: [x2 x1 x0 1] -> [x2 x0 x1]
// Example with n=2: [x2 x1 x0 2] -> [x1 x0 x2]
func opcodeRoll(op *opcode, data []byte, vm *Engine) error {
	val, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	return vm.dstack.RollN(val.Int32())
}

// opcodeRot rotates the top 3 items on the data stack to the left.
//
// Stack transformation: [... x1 x2 x3] -> [... x2 x3 x1]
func opcodeRot(op *opcode, data []byte, vm *Engine) error {
	return vm.dstack.RotN(1)
}

// opcodeSwap swaps the top two items on the stack.
//
// Stack transformation: [... x1 x2] -> [... x2 x1]
func opcodeSwap(op *opcode, data []byte, vm *Engine) error {
	return vm.dstack.SwapN(1)
}

// opcodeTuck inserts a duplicate of the top item of the data stack before the
// second-to-top item.
//
// Stack transformation: [... x1 x2] -> [... x2 x1 x2]
func opcodeTuck(op *opcode, data []byte, vm *Engine) error {
	return vm.dstack.Tuck()
}

// opcodeSize pushes the size of the top item of the data stack onto the data
// stack.
//
// Stack transformation: [... x1] -> [... x1 len(x1)]
func opcodeSize(op *opcode, data []byte, vm *Engine) error {
	so, err := vm.dstack.PeekByteArray(0)
	if err != nil {
		return err
	}

	vm.dstack.PushInt(scriptNum(len(so)))
	return nil
}

// opcodeEqual removes the top 2 items of the data stack, compares them as raw
// bytes, and pushes the result, encoded as a boolean, back to the stack.
//
// Stack transformation: [... x1 x2] -> [... bool]
func opcodeEqual(op *opcode, data []byte, vm *Engine) error {
	a, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}
	b, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	vm.dstack.PushBool(bytes.Equal(a, b))
	return nil
}

// opcodeEqualVerify is a combination of opcodeEqual and opcodeVerify.
// Specifically, it removes the top 2 items of the data stack, compares them,
// and pushes the result, encoded as a boolean, back to the stack.  Then, it
// examines the top item on the data stack as a boolean value and verifies it
// evaluates to true.  An error is returned if it does not.
//
// Stack transformation: [... x1 x2] -> [... bool] -> [...]
func opcodeEqualVerify(op *opcode, data []byte, vm *Engine) error {
	err := opcodeEqual(op, data, vm)
	if err == nil {
		err = abstractVerify(op, vm, txscript.ErrEqualVerify)
	}
	return err
}

// opcode1Add treats the top item on the data stack as an integer and replaces
// it with its incremented value (plus 1).
//
// Stack transformation: [... x1 x2] -> [... x1 x2+1]
func opcode1Add(op *opcode, data []byte, vm *Engine) error {
	m, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	vm.dstack.PushInt(m + 1)
	return nil
}

// opcode1Sub treats the top item on the data stack as an integer and replaces
// it with its decremented value (minus 1).
//
// Stack transformation: [... x1 x2] -> [... x1 x2-1]
func opcode1Sub(op *opcode, data []byte, vm *Engine) error {
	m, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}
	vm.dstack.PushInt(m - 1)

	return nil
}

// opcodeNegate treats the top item on the data stack as an integer and replaces
// it with its negation.
//
// Stack transformation: [... x1 x2] -> [... x1 -x2]
func opcodeNegate(op *opcode, data []byte, vm *Engine) error {
	m, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	vm.dstack.PushInt(-m)
	return nil
}

// opcodeAbs treats the top item on the data stack as an integer and replaces it
// it with its absolute value.
//
// Stack transformation: [... x1 x2] -> [... x1 abs(x2)]
func opcodeAbs(op *opcode, data []byte, vm *Engine) error {
	m, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if m < 0 {
		m = -m
	}
	vm.dstack.PushInt(m)
	return nil
}

// opcodeNot treats the top item on the data stack as an integer and replaces
// it with its "inverted" value (0 becomes 1, non-zero becomes 0).
//
// NOTE: While it would probably make more sense to treat the top item as a
// boolean, and push the opposite, which is really what the intention of this
// opcode is, it is extremely important that is not done because integers are
// interpreted differently than booleans and the consensus rules for this opcode
// dictate the item is interpreted as an integer.
//
// Stack transformation (x2==0): [... x1 0] -> [... x1 1]
// Stack transformation (x2!=0): [... x1 1] -> [... x1 0]
// Stack transformation (x2!=0): [... x1 17] -> [... x1 0]
func opcodeNot(op *opcode, data []byte, vm *Engine) error {
	m, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if m == 0 {
		vm.dstack.PushInt(scriptNum(1))
	} else {
		vm.dstack.PushInt(scriptNum(0))
	}
	return nil
}

// opcode0NotEqual treats the top item on the data stack as an integer and
// replaces it with either a 0 if it is zero, or a 1 if it is not zero.
//
// Stack transformation (x2==0): [... x1 0] -> [... x1 0]
// Stack transformation (x2!=0): [... x1 1] -> [... x1 1]
// Stack transformation (x2!=0): [... x1 17] -> [... x1 1]
func opcode0NotEqual(op *opcode, data []byte, vm *Engine) error {
	m, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if m != 0 {
		m = 1
	}
	vm.dstack.PushInt(m)
	return nil
}

// opcodeAdd treats the top two items on the data stack as integers and replaces
// them with their sum.
//
// Stack transformation: [... x1 x2] -> [... x1+x2]
func opcodeAdd(op *opcode, data []byte, vm *Engine) error {
	v0, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	v1, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	vm.dstack.PushInt(v0 + v1)
	return nil
}

// opcodeSub treats the top two items on the data stack as integers and replaces
// them with the result of subtracting the top entry from the second-to-top
// entry.
//
// Stack transformation: [... x1 x2] -> [... x1-x2]
func opcodeSub(op *opcode, data []byte, vm *Engine) error {
	v0, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	v1, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	vm.dstack.PushInt(v1 - v0)
	return nil
}

// opcodeBoolAnd treats the top two items on the data stack as integers.  When
// both of them are not zero, they are replaced with a 1, otherwise a 0.
//
// Stack transformation (x1==0, x2==0): [... 0 0] -> [... 0]
// Stack transformation (x1!=0, x2==0): [... 5 0] -> [... 0]
// Stack transformation (x1==0, x2!=0): [... 0 7] -> [... 0]
// Stack transformation (x1!=0, x2!=0): [... 4 8] -> [... 1]
func opcodeBoolAnd(op *opcode, data []byte, vm *Engine) error {
	v0, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	v1, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if v0 != 0 && v1 != 0 {
		vm.dstack.PushInt(scriptNum(1))
	} else {
		vm.dstack.PushInt(scriptNum(0))
	}

	return nil
}

// opcodeBoolOr treats the top two items on the data stack as integers.  When
// either of them are not zero, they are replaced with a 1, otherwise a 0.
//
// Stack transformation (x1==0, x2==0): [... 0 0] -> [... 0]
// Stack transformation (x1!=0, x2==0): [... 5 0] -> [... 1]
// Stack transformation (x1==0, x2!=0): [... 0 7] -> [... 1]
// Stack transformation (x1!=0, x2!=0): [... 4 8] -> [... 1]
func opcodeBoolOr(op *opcode, data []byte, vm *Engine) error {
	v0, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	v1, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if v0 != 0 || v1 != 0 {
		vm.dstack.PushInt(scriptNum(1))
	} else {
		vm.dstack.PushInt(scriptNum(0))
	}

	return nil
}

// opcodeNumEqual treats the top two items on the data stack as integers.  When
// they are equal, they are replaced with a 1, otherwise a 0.
//
// Stack transformation (x1==x2): [... 5 5] -> [... 1]
// Stack transformation (x1!=x2): [... 5 7] -> [... 0]
func opcodeNumEqual(op *opcode, data []byte, vm *Engine) error {
	v0, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	v1, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if v0 == v1 {
		vm.dstack.PushInt(scriptNum(1))
	} else {
		vm.dstack.PushInt(scriptNum(0))
	}

	return nil
}

// opcodeNumEqualVerify is a combination of opcodeNumEqual and opcodeVerify.
//
// Specifically, treats the top two items on the data stack as integers.  When
// they are equal, they are replaced with a 1, otherwise a 0.  Then, it examines
// the top item on the data stack as a boolean value and verifies it evaluates
// to true.  An error is returned if it does not.
//
// Stack transformation: [... x1 x2] -> [... bool] -> [...]
func opcodeNumEqualVerify(op *opcode, data []byte, vm *Engine) error {
	err := opcodeNumEqual(op, data, vm)
	if err == nil {
		err = abstractVerify(op, vm, txscript.ErrNumEqualVerify)
	}
	return err
}

// opcodeNumNotEqual treats the top two items on the data stack as integers.
// When they are NOT equal, they are replaced with a 1, otherwise a 0.
//
// Stack transformation (x1==x2): [... 5 5] -> [... 0]
// Stack transformation (x1!=x2): [... 5 7] -> [... 1]
func opcodeNumNotEqual(op *opcode, data []byte, vm *Engine) error {
	v0, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	v1, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if v0 != v1 {
		vm.dstack.PushInt(scriptNum(1))
	} else {
		vm.dstack.PushInt(scriptNum(0))
	}

	return nil
}

// opcodeLessThan treats the top two items on the data stack as integers.  When
// the second-to-top item is less than the top item, they are replaced with a 1,
// otherwise a 0.
//
// Stack transformation: [... x1 x2] -> [... bool]
func opcodeLessThan(op *opcode, data []byte, vm *Engine) error {
	v0, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	v1, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if v1 < v0 {
		vm.dstack.PushInt(scriptNum(1))
	} else {
		vm.dstack.PushInt(scriptNum(0))
	}

	return nil
}

// opcodeGreaterThan treats the top two items on the data stack as integers.
// When the second-to-top item is greater than the top item, they are replaced
// with a 1, otherwise a 0.
//
// Stack transformation: [... x1 x2] -> [... bool]
func opcodeGreaterThan(op *opcode, data []byte, vm *Engine) error {
	v0, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	v1, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if v1 > v0 {
		vm.dstack.PushInt(scriptNum(1))
	} else {
		vm.dstack.PushInt(scriptNum(0))
	}
	return nil
}

// opcodeLessThanOrEqual treats the top two items on the data stack as integers.
// When the second-to-top item is less than or equal to the top item, they are
// replaced with a 1, otherwise a 0.
//
// Stack transformation: [... x1 x2] -> [... bool]
func opcodeLessThanOrEqual(op *opcode, data []byte, vm *Engine) error {
	v0, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	v1, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if v1 <= v0 {
		vm.dstack.PushInt(scriptNum(1))
	} else {
		vm.dstack.PushInt(scriptNum(0))
	}
	return nil
}

// opcodeGreaterThanOrEqual treats the top two items on the data stack as
// integers.  When the second-to-top item is greater than or equal to the top
// item, they are replaced with a 1, otherwise a 0.
//
// Stack transformation: [... x1 x2] -> [... bool]
func opcodeGreaterThanOrEqual(op *opcode, data []byte, vm *Engine) error {
	v0, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	v1, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if v1 >= v0 {
		vm.dstack.PushInt(scriptNum(1))
	} else {
		vm.dstack.PushInt(scriptNum(0))
	}

	return nil
}

// opcodeMin treats the top two items on the data stack as integers and replaces
// them with the minimum of the two.
//
// Stack transformation: [... x1 x2] -> [... min(x1, x2)]
func opcodeMin(op *opcode, data []byte, vm *Engine) error {
	v0, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	v1, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if v1 < v0 {
		vm.dstack.PushInt(v1)
	} else {
		vm.dstack.PushInt(v0)
	}

	return nil
}

// opcodeMax treats the top two items on the data stack as integers and replaces
// them with the maximum of the two.
//
// Stack transformation: [... x1 x2] -> [... max(x1, x2)]
func opcodeMax(op *opcode, data []byte, vm *Engine) error {
	v0, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	v1, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if v1 > v0 {
		vm.dstack.PushInt(v1)
	} else {
		vm.dstack.PushInt(v0)
	}

	return nil
}

// opcodeWithin treats the top 3 items on the data stack as integers.  When the
// value to test is within the specified range (left inclusive), they are
// replaced with a 1, otherwise a 0.
//
// The top item is the max value, the second-top-item is the minimum value, and
// the third-to-top item is the value to test.
//
// Stack transformation: [... x1 min max] -> [... bool]
func opcodeWithin(op *opcode, data []byte, vm *Engine) error {
	maxVal, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	minVal, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	x, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if x >= minVal && x < maxVal {
		vm.dstack.PushInt(scriptNum(1))
	} else {
		vm.dstack.PushInt(scriptNum(0))
	}
	return nil
}

// calcHash calculates the hash of hasher over buf.
func calcHash(buf []byte, hasher hash.Hash) []byte {
	hasher.Write(buf)
	return hasher.Sum(nil)
}

// opcodeRipemd160 treats the top item of the data stack as raw bytes and
// replaces it with ripemd160(data).
//
// Stack transformation: [... x1] -> [... ripemd160(x1)]
func opcodeRipemd160(op *opcode, data []byte, vm *Engine) error {
	buf, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	vm.dstack.PushByteArray(calcHash(buf, ripemd160.New()))
	return nil
}

// opcodeSha1 treats the top item of the data stack as raw bytes and replaces it
// with sha1(data).
//
// Stack transformation: [... x1] -> [... sha1(x1)]
func opcodeSha1(op *opcode, data []byte, vm *Engine) error {
	buf, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	hash := sha1.Sum(buf)
	vm.dstack.PushByteArray(hash[:])
	return nil
}

// opcodeSha256 treats the top item of the data stack as raw bytes and replaces
// it with sha256(data).
//
// Stack transformation: [... x1] -> [... sha256(x1)]
func opcodeSha256(op *opcode, data []byte, vm *Engine) error {
	buf, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	hash := sha256.Sum256(buf)
	vm.dstack.PushByteArray(hash[:])
	return nil
}

// opcodeHash160 treats the top item of the data stack as raw bytes and replaces
// it with ripemd160(sha256(data)).
//
// Stack transformation: [... x1] -> [... ripemd160(sha256(x1))]
func opcodeHash160(op *opcode, data []byte, vm *Engine) error {
	buf, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	hash := sha256.Sum256(buf)
	vm.dstack.PushByteArray(calcHash(hash[:], ripemd160.New()))
	return nil
}

// opcodeHash256 treats the top item of the data stack as raw bytes and replaces
// it with sha256(sha256(data)).
//
// Stack transformation: [... x1] -> [... sha256(sha256(x1))]
func opcodeHash256(op *opcode, data []byte, vm *Engine) error {
	buf, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	vm.dstack.PushByteArray(chainhash.DoubleHashB(buf))
	return nil
}

func opcodeSigDisabled(op *opcode, data []byte, vm *Engine) error {
	return scriptError(txscript.ErrDisabledOpcode, fmt.Sprintf("attempt to execute disabled opcode %s", op.name))
}

// OpcodeByName is a map that can be used to lookup an opcode by its
// human-readable name (OP_CHECKMULTISIG, OP_CHECKSIG, etc).
var OpcodeByName = make(map[string]byte)

func init() {
	// Initialize the opcode name to value map using the contents of the
	// opcode array.  Also add entries for "OP_FALSE", "OP_TRUE", and
	// "OP_NOP2" since they are aliases for "OP_0", "OP_1",
	// and "OP_CHECKLOCKTIMEVERIFY" respectively.
	for _, op := range opcodeArray {
		OpcodeByName[op.name] = op.value
	}
	OpcodeByName["OP_FALSE"] = txscript.OP_FALSE
	OpcodeByName["OP_TRUE"] = txscript.OP_TRUE
	OpcodeByName["OP_NOP2"] = txscript.OP_CHECKLOCKTIMEVERIFY
	OpcodeByName["OP_NOP3"] = txscript.OP_CHECKSEQUENCEVERIFY
}
