import Random from "./random";
import { choose, many, oneOf } from "./combinators";
import {IDENTIFIER_START, IDENTIFIER_CONTINUE} from "./unicode";
import propertyValues from 'unicode-match-property-value-ecmascript/data/mappings.js';
import canonicalProperties from 'unicode-canonical-property-names-ecmascript/index.js';

function testRegExp(regexp, flags = '', constructor = RegExp) {
  try {
    return constructor(regexp, flags);
  } catch (e) {
    return false;
  }
}

export class RegExpBugAvoidanceConfiguration {
  constructor({namedGroups = true, lookbehinds = true, unicodeProperties = true, loneUnicodePropertiesBroken = [], loneUnicodeProperties = utf16LonePropertyValuesRaw.filter(value => loneUnicodePropertiesBroken.indexOf(value) === -1)} = {}) {
    this.namedGroups = namedGroups;
    this.unicodeProperties = unicodeProperties;
    this.loneUnicodePropertiesBroken = loneUnicodePropertiesBroken;
    this.loneUnicodeProperties = loneUnicodeProperties;
    this.lookbehinds = lookbehinds;
  }

  static fromEngine(constructor = RegExp) {
    return new RegExpBugAvoidanceConfiguration({namedGroups: !!testRegExp('(?<t>)', '', constructor), lookbehinds: !!testRegExp('(?<=)(?<!)', '', constructor), unicodeProperties: !!testRegExp('\\p{ASCII}', 'u', constructor), loneUnicodePropertiesBroken: defaultBrokenLoneUnicodeValues(constructor)});
  }
}

class RegExpGlobalState {
  constructor() {
    this.definedGroupSpecifiers = [];
    this.groupSpecifiersToDefine = [];
    this.noNumericLookahead = false;
  }
}

class RegExpState {
  constructor({maxDepth = 5, rng = new Random(Math.random), unicode = false, requireQuantifiable = false, inClass = false, maxNumber = 100000, globalState = new RegExpGlobalState(), bugAvoidance = new RegExpBugAvoidanceConfiguration()} = {}) {
    this.maxDepth = maxDepth;
    this.depth = 0;
    this.rng = rng;
    this.unicode = unicode;
    this.requireQuantifiable = requireQuantifiable;
    this.inClass = inClass;
    this.maxNumber = maxNumber;
    this.globalState = globalState;
    this.bugAvoidance = bugAvoidance;
  }

  tooDeep() {
    return this.depth >= this.maxDepth;
  }

  clone() {
    let st = new RegExpState({maxDepth: this.maxDepth, rng: this.rng, unicode: this.unicode, requireQuantifiable: this.requireQuantifiable, inClass: this.inClass, maxNumber: this.maxNumber, globalState: this.globalState, bugAvoidance: this.bugAvoidance});
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
  return String.fromCharCode(32 + f.rng.nextInt(94));
}

const fuzzHexExcept = (f, except) => oneOf(...'01234567890abcdefABCDEF'.split('').filter(hex => except.indexOf(hex) === -1))(f);

const fuzzHex = oneOf('0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f','A','B','C','D','E','F');

const decimal = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'];

const syntaxCharacters = '^$\\.*+?()[{|'.split('');

const unicodeSyntaxCharacters = '^$\\.*+?()[]{}|';

const controlLetters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'.split('');

const getSyntaxCharacters = state => state.unicode ? unicodeSyntaxCharacters : syntaxCharacters;

const utf16GeneralCategoryValues = Array.from(propertyValues.get('General_Category').keys());

const utf16ScriptCategoryValues = Array.from(propertyValues.get('Script').keys());

const utf16NonBinaryPropertyNames = {
  General_Category: utf16GeneralCategoryValues,
  gc: utf16GeneralCategoryValues,
  Script: utf16ScriptCategoryValues,
  sc: utf16ScriptCategoryValues,
  Script_Extensions: utf16ScriptCategoryValues,
  scx: utf16ScriptCategoryValues,
};

const utf16LonePropertyValuesRaw = Array.from(canonicalProperties.keys()).filter(property => !(property in utf16NonBinaryPropertyNames));

//NOTE: this is *really* slow, as you can imagine. the only value that I have found to fail is Extended_Pictographic, and we may want to hardcode it.
let defaultBrokenLoneUnicodeValuesCached;
let defaultBrokenLoneUnicodeValuesCachedConstructor;

const defaultBrokenLoneUnicodeValuesCalculate = () => !testRegExp('\\p{ASCII}', 'u') ? [] : utf16LonePropertyValuesRaw.filter(value => !testRegExp(`/\\p{${value}}`, 'u'));

const defaultBrokenLoneUnicodeValues = (constructor) => {
  if (defaultBrokenLoneUnicodeValuesCachedConstructor !== constructor) {
    defaultBrokenLoneUnicodeValuesCachedConstructor = constructor;
    defaultBrokenLoneUnicodeValuesCached = void 0;
  }
  return defaultBrokenLoneUnicodeValuesCached || (defaultBrokenLoneUnicodeValuesCached = defaultBrokenLoneUnicodeValuesCalculate())
};

const fuzzLoneUnicodePropertyNameOrValue = f => f.bugAvoidance.loneUnicodeProperties[f.rng.nextInt(f.bugAvoidance.loneUnicodeProperties.length)];

const fuzzUnicodePropertyNameAndValue = f => {
  let propertyName = oneOf(...Object.keys(utf16NonBinaryPropertyNames))(f);
  let possibleValues = utf16NonBinaryPropertyNames[propertyName]
  let value = possibleValues[f.rng.nextInt(possibleValues.length)];
  return `${propertyName}=${value}`;
}

const fuzzUnicodePropertyValueExpression = choose(fuzzUnicodePropertyNameAndValue, fuzzLoneUnicodePropertyNameOrValue);

const fuzzUnicodeEscape = onlyUnicode => state => {
  let unicodeFuzzers = [];
  if (state.unicode) {
    let firstFuzzedHex = null;
    if (!onlyUnicode && state.bugAvoidance.unicodeProperties) {
      unicodeFuzzers.push(
        f => `\\${oneOf('p', 'P')(f)}{${fuzzUnicodePropertyValueExpression(f)}}`, // unicode character class escape
        f => `\\${oneOf(...syntaxCharacters, '/')(f)}`, // syntax characters, including .
      );
    }
    unicodeFuzzers.push(
      f => `\\u{${firstFuzzedHex = fuzzHex(f)}${firstFuzzedHex === 'd' || firstFuzzedHex === 'D' ? fuzzHexExcept(f, '89abcdefABCDEF'.split('')) : fuzzHex(f)}${fuzzHex(f)}${fuzzHex(f)}}`,
      f => `\\u${firstFuzzedHex = fuzzHex(f)}${firstFuzzedHex === 'd' || firstFuzzedHex === 'D' ? fuzzHexExcept(f, '89abcdefABCDEF'.split('')) : fuzzHex(f)}${fuzzHex(f)}${fuzzHex(f)}`,
      f => `\\u{${fuzzHexExcept(f, ['0'])}${fuzzHex(f)}${fuzzHex(f)}${fuzzHex(f)}${fuzzHex(f)}}`,
      f => `\\u{10${fuzzHex(f)}${fuzzHex(f)}${fuzzHex(f)}${fuzzHex(f)}}`,
      f => `\\u${oneOf('d', 'D')(f)}${oneOf('8', '9', 'A', 'B', 'a', 'b')(f)}${fuzzHex(f)}${fuzzHex(f)}\\uD${oneOf('C', 'D', 'E', 'F', 'c', 'd', 'e', 'f')(f)}${fuzzHex(f)}${fuzzHex(f)}`
    );
  } else {
    unicodeFuzzers.push(
      f => `\\u${fuzzHex(f)}${fuzzHex(f)}${fuzzHex(f)}${fuzzHex(f)}`
    );
  }
  return choose(...unicodeFuzzers)(state);
}

const octal = decimal.slice(0, 8);

const occupiedEscapes = ['d', 'D', 's', 'S', 'w', 'W', 'p', 'P', 'f', 'n', 'r', 't', 'v', 'u', 'x', 'b', 'B', 'c', 'k', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0'];

const fuzzDecimalEscape = state => {
  let nParens = state.globalState.groupSpecifiersToDefine.length + state.globalState.definedGroupSpecifiers.length;
  if (nParens === 0) {
    state.globalState.groupSpecifiersToDefine.push(fuzzRegExpIdentifierWithValue(state));
    nParens++;
  }
  return `\\${state.rng.nextInt(nParens) + 1}`
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

const fuzzCodePoint = characters => f => {
  let codePoint = characters[f.rng.nextInt(characters.length)].codePointAt(0);
  let encoders = [
    () => {
      if (codePoint < 0x10000) {
        return `\\u${padHex(codePoint.toString(16), 4)}`
      } else {
        let pair = encodeSurrogatePair(codePoint);
        return pair.map(point => `\\u${padHex(point.toString(16), 4)}`).join('');
      }
    },
  ];
  if (f.unicode) {
    encoders.push(() => `\\u{${codePoint.toString(16)}}`);
  }
  return choose(...encoders)();
};

const IDENTIFIER_START_ASCII = IDENTIFIER_START.filter(v => v.codePointAt(0) < 128);
const IDENTIFIER_CONTINUE_ASCII = IDENTIFIER_CONTINUE.filter(v => v.codePointAt(0) < 128);

const fuzzIdentifierContinue = f => fuzzCharacters(f.unicode ? IDENTIFIER_CONTINUE : IDENTIFIER_CONTINUE_ASCII)(f);

const fuzzCodePointIdentifierContinue = f => fuzzCodePoint(f.unicode ? IDENTIFIER_CONTINUE : IDENTIFIER_CONTINUE_ASCII)(f);

const fuzzIdentifierStart = f => fuzzCharacters(f.unicode ? IDENTIFIER_START : IDENTIFIER_START_ASCII)(f);

const fuzzCodePointIdentifierStart = f => fuzzCodePoint(f.unicode ? IDENTIFIER_START : IDENTIFIER_START_ASCII)(f);

const fuzzSpecialIdentifierContinueCharacter = f => oneOf('\u200C', '\u200D')(f); // ZWNJ / ZWJ

const fuzzRegExpIdentifier = state => {
  return `${choose(f => oneOf('$', '_')(f), fuzzCodePointIdentifierStart, fuzzIdentifierStart)(state)}${many(choose(f => '$', fuzzCodePointIdentifierContinue, fuzzIdentifierContinue, fuzzSpecialIdentifierContinueCharacter))(state).join('')}`;
}

const fuzzRegExpIdentifierWithValue = state => {
  let identifier;
  let value;
  do {
    identifier = fuzzRegExpIdentifier(state);
    let identifierFiltered = identifier.replace(/\\u\{[0-9a-fA-F]+\}/g, (matched) => encodeSurrogatePair(parseInt(matched.slice(3), 16)).map(num => `\\u${padHex(num.toString(16), 4)}`).join(''));
    value = JSON.parse(`"${identifierFiltered}"`);
  } while(state.globalState.definedGroupSpecifiers.find(obj => obj.value === value) || state.globalState.groupSpecifiersToDefine.find(obj => obj.value === value));
  return {identifier, value};
}

const fuzzRegExpIdentifierDeclaration = state => {
  let identifier
  let value;
  if (state.globalState.groupSpecifiersToDefine.length > 0) {
    ({identifier, value} = state.globalState.groupSpecifiersToDefine.pop());
  } else {
    ({identifier, value} = fuzzRegExpIdentifierWithValue(state));
  }
  state.globalState.definedGroupSpecifiers.push({identifier, value});
  return identifier;
}

const fuzzRegExpIdentifierReference = state => {
  if (state.globalState.definedGroupSpecifiers.length === 0) {
    if (state.globalState.groupSpecifiersToDefine.length === 0) {
      state.globalState.groupSpecifiersToDefine.push(fuzzRegExpIdentifierWithValue(state));
    }
    return state.globalState.groupSpecifiersToDefine[state.rng.nextInt(state.globalState.groupSpecifiersToDefine.length)].identifier;
  }
  return state.globalState.definedGroupSpecifiers[state.rng.nextInt(state.globalState.definedGroupSpecifiers.length)].identifier;
}

const fuzzGroupName = (f, isDeclaration) => `<${isDeclaration ? fuzzRegExpIdentifierDeclaration(f) : fuzzRegExpIdentifierReference(f)}>`

const fuzzGroupSpecifier = (f, isDeclaration) => !f.bugAvoidance.namedGroups ? '' : choose(f => '', f => `?${fuzzGroupName(f, isDeclaration)}`)(f);

const fuzzGrouping = f => {
  if (f.tooDeep()) return '()';
  f = f.goDeeper();
  f.globalState.noNumericLookahead = false;
  let spec = fuzzGroupSpecifier(f, true);
  let value = `(${spec}${fuzzDisjunction(f)})`;
  f.globalState.noNumericLookahead = false;
  return value;
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
    fuzzGrouping,
    fuzzNoCaptureGrouping,
    // invalid braced quantifier intentionally never generated ... it is always an error
  ];
  if (state.bugAvoidance.namedGroups) {
    characterFuzzers.push(f => `\\k${fuzzGroupName(f, false)}`);
  }
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

const illegalRangeItems = ['\\c', '\\k'];
const illegalRangeItemsUnicode = ['\\d', '\\D', '\\w', '\\W', '\\s', '\\S', '\\c', '\\k', '\\p', '\\P'];

const fuzzCharacterClassRange = canDash => f => {
  let toCheckItems = illegalRangeItems;
  if (f.unicode) {
    toCheckItems = illegalRangeItemsUnicode;
  }
  let a = guardValue(fuzzClassAtom, value => value.length == 0 || toCheckItems.filter(item => value.startsWith(item)).length > 0)(f);
  let b = guardValue(fuzzClassAtom, value => value.length == 0 || toCheckItems.filter(item => value.startsWith(item)).length > 0)(f);
  let valueA = charVal(a);
  let valueB = charVal(b);
  if (valueA > valueB) {
    [a, b] = [b, a];
  }
  if (canDash && '-'.charCodeAt(0) < valueB) {
    a = oneOf(a, '-')(f);
    valueA = charVal(a);
  }
  if ('-'.charCodeAt(0) >= valueA) {
    b = oneOf(b, '-')(f);
    valueB = charVal(b);
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

const lookarounds = ['?=', '?!', '?<=', '?<!'];
const lookaheads = ['?=', '?!'];

const fuzzAssertion = f => choose(oneOf('^', '$', '\\b', '\\B'), f => fuzzLookaroundGrouping(f.bugAvoidance.lookbehinds ? lookarounds : lookaheads)(f))(f);

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

export function engineSupportsRegExpUnicode() {
  let regexp = testRegExp('()', 'u');
  return !!regexp && !!regexp.unicode;
}

export default function fuzzRegExpPattern(f = {rng: new Random(Math.random)}, unicode = false, bugAvoidance = new RegExpBugAvoidanceConfiguration()) {
  let state = new RegExpState({rng: f.rng, unicode: unicode, bugAvoidance: bugAvoidance});
  let rv = fuzzDisjunction(state);
  while (state.globalState.groupSpecifiersToDefine.length > 0) {
    if (state.bugAvoidance.namedGroups) {
      rv += `(?<${state.globalState.groupSpecifiersToDefine.pop().identifier}>)`;
    } else {
      state.globalState.groupSpecifiersToDefine.pop();
      rv += `()`;
    }
  }
  if (rv === '') return '(?:)';
  return rv;
}
