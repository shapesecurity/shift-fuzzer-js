import { isIdentifierStart, isIdentifierPart } from 'shift-parser/dist/utils.js';

export const { IDENTIFIER_START, IDENTIFIER_CONTINUE } = (() => {
	let starts = [];
	let continues = [];
	
	for (let i = 0; i <= 0x100000; i++) {
		if (isIdentifierStart(i)) {
			starts.push(String.fromCodePoint(i));
		}
		if (isIdentifierPart(i)) {
			continues.push(String.fromCodePoint(i));
		}
	}
	return { IDENTIFIER_START: starts, IDENTIFIER_CONTINUE: continues };
})();
