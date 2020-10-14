const Random = require("./random");
const { choose, many, oneOf } = require("./combinators");
const { IDENTIFIER_START, IDENTIFIER_CONTINUE } = require("./unicode");
const { FuzzerState } = require('./fuzzer-state');

class RegExpGlobalState {
  constructor() {
    this.noNumericLookahead = false;
    this.maxGroupSecifier = 0;
  }
}

class RegExpState {
  constructor({ maxDepth = 5, rng = new Random(Math.random), unicode = false, requireQuantifiable = false, inClass = false, maxNumber = 100000, globalState = new RegExpGlobalState() }) {
    this.maxDepth = maxDepth;
    this.depth = 0;
    this.rng = rng;
    this.unicode = unicode;
    this.requireQuantifiable = requireQuantifiable;
    this.inClass = inClass;
    this.maxNumber = maxNumber;
    this.globalState = globalState;
  }

  tooDeep() {
    return this.depth >= this.maxDepth;
  }

  clone() {
    let st = new RegExpState({ maxDepth: this.maxDepth, rng: this.rng, unicode: this.unicode, requireQuantifiable: this.requireQuantifiable, inClass: this.inClass, maxNumber: this.maxNumber, globalState: this.globalState });
    st.depth = this.depth;
    return st;
  }

  goDeeper() {
    let st = this.clone();
    ++st.depth;
    return st;
  }
}

const charVal = c => {
  if (c[0] === '\\') {
    switch (c[1]) {
      case 'u':;
        let nextIndex = c.indexOf('\\u', 2);
        if (nextIndex === -1) {
          let braceOffset = c[2] === '{' ? 1 : 0;
          return parseInt(c.slice(2 + braceOffset, c.length - braceOffset), 16);
        } else { // surrogate pair
          let value = 0x10000;
          value += (parseInt(c.slice(2, nextIndex), 16) & 0x03FF) << 10;
          value += parseInt(c.slice(nextIndex + 2, c.length), 16) & 0x03FF;
          return value;
        }
      case 'x':
        return parseInt(c.slice(2), 16);
      case '0':
      case '1':
      case '2':
      case '3':
      case '4':
      case '5':
      case '6':
      case '7':
        return parseInt(c.slice(1), 8);
      case 'b':
        return 8;
      case 't':
        return 9;
      case 'n':
        return 10;
      case 'v':
        return 11;
      case 'f':
        return 12;
      case 'r':
        return 13;
      case 'c':
        throw new Error('control sequences not supported');
      default:
        return c.codePointAt(1);
    }
  } else {
    return c.codePointAt(0);
  }
};


const fuzzPrintableAscii = f => {
  let o = 32 + f.rng.nextInt(94);
  while (o === 47) { // exclude `/`, which cannot appear unescaped in regexp literals
    o = 32 + f.rng.nextInt(94);
  }
  return String.fromCharCode(o);
}

const fuzzHexExcept = (f, except) => oneOf(...'01234567890abcdefABCDEF'.split('').filter(hex => except.indexOf(hex) === -1))(f);

const fuzzHex = oneOf('0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f','A','B','C','D','E','F');

const decimal = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'];

const syntaxCharacters = '^$\\.*+?()[{|'.split('');

const unicodeSyntaxCharacters = '^$\\.*+?()[]{}|';

const controlLetters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'.split('');

const getSyntaxCharacters = state => state.unicode ? unicodeSyntaxCharacters : syntaxCharacters;

const fuzzUnicodeEscape = onlyUnicode => state => {
  let unicodeFuzzers = [];
  if (state.unicode) {
    let firstFuzzedHex = null;
    unicodeFuzzers.push(
      f => `\\u{${firstFuzzedHex = fuzzHex(f)}${firstFuzzedHex === 'd' || firstFuzzedHex === 'D' ? fuzzHexExcept(f, '89abcdefABCDEF'.split('')) : fuzzHex(f)}${fuzzHex(f)}${fuzzHex(f)}}`,
      f => `\\u${firstFuzzedHex = fuzzHex(f)}${firstFuzzedHex === 'd' || firstFuzzedHex === 'D' ? fuzzHexExcept(f, '89abcdefABCDEF'.split('')) : fuzzHex(f)}${fuzzHex(f)}${fuzzHex(f)}`,
      f => `\\u{${fuzzHexExcept(f, ['0'])}${fuzzHex(f)}${fuzzHex(f)}${fuzzHex(f)}${fuzzHex(f)}}`,
      f => `\\u{10${fuzzHex(f)}${fuzzHex(f)}${fuzzHex(f)}${fuzzHex(f)}}`,
      f => `\\u${oneOf('d', 'D')(f)}${oneOf('8', '9', 'A', 'B', 'a', 'b')(f)}${fuzzHex(f)}${fuzzHex(f)}\\u${oneOf('d', 'D')(f)}${oneOf('C', 'D', 'E', 'F', 'c', 'd', 'e', 'f')(f)}${fuzzHex(f)}${fuzzHex(f)}`
    );
  } else {
    unicodeFuzzers.push(
      f => `\\u${fuzzHex(f)}${fuzzHex(f)}${fuzzHex(f)}${fuzzHex(f)}`
    );
  }
  return choose(...unicodeFuzzers)(state);
}

const octal = decimal.slice(0, 8);

const occupiedEscapes = ['d', 'D', 's', 'S', 'w', 'W', 'f', 'n', 'r', 't', 'v', 'u', 'x', 'b', 'B', 'c', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0'];

const fuzzDecimalEscape = state => {
  let specifier = state.rng.nextInt(9) + 1; // [1, 9]
  state.globalState.maxGroupSecifier = Math.max(state.globalState.maxGroupSecifier, specifier);
  return `\\${specifier}`
}

const fuzzCharacterEscapes = state => {
  let characterFuzzers = [
    f => `\\${oneOf('d', 'D', 's', 'S', 'w', 'W')(f)}`, // character class escape
    f => `\\${oneOf('f', 'n', 'r', 't', 'v')(f)}`, // control escape
    f => `\\c${oneOf(...controlLetters)(f)}`, // control letter escape
    f => `\\x${fuzzHex(f)}${fuzzHex(f)}`, // hex escape
    fuzzUnicodeEscape(false),
    f => '\\0', // no octal lookahead, always evaluates to 0x0
  ];
  if (!state.unicode) {
    characterFuzzers.push(
      f => `\\${choose( // legacy octal escape
        oneOf(...octal),
        f => `${oneOf(...octal.slice(0, 4))(f)}${oneOf(...octal)(f)}${choose((f => ''), oneOf(...octal))(f)}`,
        f => `${oneOf(...octal.slice(4))(f)}${oneOf(...octal)(f)}`
      )(f)}`,
      f => {
        let c;
        do {
          c = fuzzPrintableAscii(f);
        } while (occupiedEscapes.indexOf(c) !== -1);
        return `\\${c}`;
      }
    );
  }
  return choose(...characterFuzzers)(state);
};

const fuzzPrintableAsciiExcept = except => f => {
  let c;
  do {
    c = fuzzPrintableAscii(f);
  } while (except.indexOf(c) !== -1);
  return c;
};

const fuzzPatternCharacter = f => fuzzPrintableAsciiExcept(getSyntaxCharacters(f))(f);

const fuzzCharacters = characters => f => characters[f.rng.nextInt(characters.length)];

const padHex = (str, length) => {
  if (str.length >= length) {
     return str;
  }
  for (let i = str.length; i < length; i++) {
    str = '0' + str;
  }
  return str;
}

const encodeSurrogatePair = codePoint => {
  if (codePoint < 0x10000) {
    return [codePoint];
  }
  codePoint -= 0x10000;
  return [0xD800 | (codePoint >> 10), 0xDC00 | (codePoint & 0x3FF)];
}

const fuzzNoCaptureGrouping = f => {
  if (f.tooDeep()) return '()';
  f = f.goDeeper();
  f.globalState.noNumericLookahead = false;
  let value = `(?:${fuzzDisjunction(f)})`;
  f.globalState.noNumericLookahead = false;
  return value;
}

const fuzzLookaroundGrouping = groups => f => {
  if (f.tooDeep()) return '()';
  f = f.goDeeper();
  f.globalState.noNumericLookahead = false;
  let value = `(${oneOf(...groups)(f)}${fuzzDisjunction(f)})`;
  f.globalState.noNumericLookahead = false;
  return value;
}

const guardValue = (fuzzer, predicate) => state => {
  let value;
  do {
    value = fuzzer(state);
  } while (predicate(value));
  return value;
}

const guardEscapedNumeric = (initialState, fuzzer) => {
  let protectedValues = initialState.unicode ? decimal : octal;
  let guardedFunction = guardValue(fuzzer, value => protectedValues.indexOf(value.charAt(0)) !== -1);
  return state => {
    let value;
    if (state.globalState.noNumericLookahead) {
      value = guardedFunction(state);
    } else {
      value = fuzzer(state);
    }
    if (value.length > 0) {
      let lastBackslashIndex = value.lastIndexOf('\\');
      state.globalState.noNumericLookahead = lastBackslashIndex >= 0 && protectedValues.indexOf(value[lastBackslashIndex + 1]) >= 0;
    }
    return value;
  };
};

const fuzzAtom = state => {
  if (state.tooDeep()) return '';
  state = state.goDeeper();
  let characterFuzzers = [
    fuzzPatternCharacter,
    fuzzCharacterEscapes,
    fuzzCharacterClass,
    fuzzNoCaptureGrouping,
    // invalid braced quantifier intentionally never generated ... it is always an error
  ];
  if (state.unicode) {
    characterFuzzers.push(fuzzDecimalEscape);
  }
  return choose(...characterFuzzers)(state);
}

const fuzzClassAtomDash = f => choose(f => '-', fuzzClassAtom)(f);

const fuzzClassAtom = state => {
  if (state.tooDeep()) return '';
  state = state.goDeeper();
  let characterFuzzers = [
    fuzzPrintableAsciiExcept(['\\', ']', '-']),
    f => `\\${oneOf(...syntaxCharacters)(f)}`,
    fuzzCharacterEscapes,
  ];
  if (state.unicode) {
    characterFuzzers.push(
      f => '\\-'
    );
  } else {
    characterFuzzers.push(
      f => `\\c${oneOf(...decimal, '_')(f)}`
    );
  }
  return choose(...characterFuzzers)(state);
};

const fuzzCharacterClass = f => {
  if (f.tooDeep()) return '[]';
  f = f.goDeeper();
  f.globalState.noNumericLookahead = false;
  let canDash = true;
  let dashRangeFuzzer = fuzzCharacterClassRange(true);
  let noDashRangeFuzzer = fuzzCharacterClassRange(false);
  let canCaret = false;
  let fuzzToken = f => {
    let lastWasRange = false;
    let value = guardEscapedNumeric(f, guardValue(choose(
      f => {
        lastWasRange = false;
        return canDash ? fuzzClassAtomDash(f) : fuzzClassAtom(f)
      },
      f => {
        lastWasRange = true;
        return canDash ? dashRangeFuzzer(f) : noDashRangeFuzzer(f)
      }
    ), value => !canCaret && value.startsWith('^')))(f);
    canDash = lastWasRange;
    canCaret = true;
    return value;
  };
  let source = many(fuzzToken)(f).join('');
  f.globalState.noNumericLookahead = false;
  return `[${oneOf('^', '')(f)}${source}${oneOf('-', '')(f)}]`;
};

const illegalRangeItems = ['\\c'];
const illegalRangeItemsUnicode = ['\\d', '\\D', '\\w', '\\W', '\\s', '\\S', '\\c'];

const fuzzCharacterClassRange = canDash => f => {
  let toCheckItems = f.unicode ? illegalRangeItemsUnicode : illegalRangeItems;
  let a = guardValue(fuzzClassAtom, value => value.length == 0 || toCheckItems.filter(item => value.startsWith(item)).length > 0)(f);
  let b = guardValue(fuzzClassAtom, value => value.length == 0 || toCheckItems.filter(item => value.startsWith(item)).length > 0)(f);
  let valueA = charVal(a);
  let valueB = charVal(b);
  if (valueA > valueB) {
    [a, b] = [b, a];
  }
  return `${a}-${b}`;
};

const fuzzLengthQuantifier = f => choose(
  f => `{${f.rng.nextInt(f.maxNumber)}${oneOf(',', '')(f)}}`,
  f => {
    let num1 = f.rng.nextInt(f.maxNumber);
    let num2;
    num2 = num1 + f.rng.nextInt(f.maxNumber - num1);
    return `{${num1},${num2}}`
  }
)(f)

const fuzzQuantifier = f => `${choose(oneOf('?', '+', '*'), fuzzLengthQuantifier)(f)}${oneOf('', '?')(f)}`;

const fuzzRepetition = fuzzer => f => {
  if (f.tooDeep()) return '';
  f = f.goDeeper();
  if (f.tooDeep()) {
    return '';
  }
  return `${fuzzer(f)}${fuzzQuantifier(f)}`;
}

const lookaheads = ['?=', '?!'];

const fuzzAssertion = f => choose(oneOf('^', '$', '\\b', '\\B'), f => fuzzLookaroundGrouping(lookaheads)(f))(f);

const fuzzTermUnicode = f => choose(fuzzAssertion, fuzzAtom, fuzzRepetition(fuzzAtom))(f);

const fuzzTermNonUnicode = f => choose(fuzzRepetition(fuzzLookaroundGrouping(lookaheads)), fuzzAssertion, fuzzAtom, fuzzRepetition(fuzzAtom))(f);

const fuzzTerm = f => f.unicode ? fuzzTermUnicode(f) : fuzzTermNonUnicode(f);

const fuzzAlternative = f => many(guardEscapedNumeric(f, fuzzTerm))(f).join('');

const fuzzManyDisjunctions = f => {
  if (f.tooDeep()) return '';
  f = f.goDeeper();
  return many(fuzzAlternative)(f).join('|');
};

const fuzzDisjunction = f => {
  if (f.tooDeep()) return '';
  f = f.goDeeper();
  return choose(fuzzAlternative, fuzzManyDisjunctions)(f);
};

module.exports = function fuzzRegExpPattern(f = new FuzzerState, unicode = false) {
  let state = new RegExpState({rng: f.rng, unicode: unicode});
  let rv = fuzzDisjunction(state);
  // TODO we should also count existing ones, to avoid adding these unnecessarily
  for (let i = 0; i < state.globalState.maxGroupSecifier; ++i) {
    rv += `()`;
  }
  if (rv === '') return '(?:)';
  return rv;
}
