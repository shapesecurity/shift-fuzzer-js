import Random from "./random";
import { choose, many, oneOf } from "./combinators";

// todo generate: /\cM/ (matches control-M in a string).

class RegExpState {
  constructor({maxDepth = 5, rng = new Random(Math.random)} = {}) {
    this.maxDepth = maxDepth;
    this.depth = 0;
    this.rng = rng;
  }

  tooDeep() {
    return this.depth >= this.maxDepth;
  }

  clone() {
    let st = new RegExpState({maxDepth: this.maxDepth, rng: this.rng});
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
      case 'u':
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
        return c.charCodeAt(1);
    }
  } else {
    return c.charCodeAt(0);
  }
};


const fuzzPrintableAscii = f => {
  return String.fromCharCode(32 + f.rng.nextInt(94));
}

const fuzzHex = oneOf(...'0123456789abcdefABCDEF');


const fuzzAlternation = f => {
  if (f.tooDeep()) return '';
  f = f.goDeeper();
  return many(choose(fuzzGrouping, fuzzCharacterClass, fuzzRepetition, fuzzSequence))(f).join('|');
};

const fuzzGrouping = f => {
  if (f.tooDeep()) return '()';
  f = f.goDeeper();
  return `(${oneOf('?:', '?!', '?=', '')(f)}${fuzzRegExpSource(f)})`;
};

const fuzzRepetition = f => {
  if (f.tooDeep()) return '';
  f = f.goDeeper();
  return `${choose(fuzzGrouping, fuzzCharacterClass, fuzzCharacter)(f)}${oneOf('?', '+', '*', '*?', '+?')(f)}`;
}

const fuzzSequence = f => many(choose(fuzzCharacter, fuzzBoundary))(f).join('');

const fuzzBoundary = oneOf('^', '$', '\\b', '\\B');

const fuzzCharacter = choose(
  f => {
    let c;
    do {
      c = fuzzPrintableAscii(f);
    } while (['[', '(', ')', '{', '?', '*', '+', '|', '\\', '$', '^', '/'].indexOf(c) !== -1);
    return c;
  },
  f => `\\u${fuzzHex(f)}${fuzzHex(f)}${fuzzHex(f)}${fuzzHex(f)}`,
  f => `\\x${fuzzHex(f)}${fuzzHex(f)}`,
  f => {
    let c;
    do {
      c = fuzzPrintableAscii(f);
    } while (['u', 'x', 'b', 'B', 'c', '1', '2', '3', '4', '5', '6', '7', '8', '9'].indexOf(c) !== -1);
    return `\\${c}`;
  }
);


const fuzzCharacterClass = f => {
  if (f.tooDeep()) return '[]';
  f = f.goDeeper();
  let source = many(choose(fuzzCharacterClassCharacter, fuzzCharacterClassRange))(f).join('');
  source = source.replace(/((^|[^\\])(\\\\)*)\\$/g, '$1\\a'); // character class cannot end in an odd number of backslashes
  return `[${oneOf('^', '-', '')(f)}${source}${oneOf('-', '')(f)}]`;
};

const fuzzCharacterClassCharacter = f => {
  let ch;
  do {
    ch = choose(fuzzCharacter, oneOf('[', '(', ')', '{', '?', '*', '+', '|', '$'))(f);
  } while (ch === '-' || ch === ']');
  return ch;
};

const fuzzCharacterClassRange = f => {
  let a = fuzzCharacterClassCharacter(f);
  let b = fuzzCharacterClassCharacter(f);
  if (charVal(b) < charVal(a)) [a, b] = [b, a];
  return `${a}-${b}`;
};





const fuzzRegExpSource = f => {
  if (f.tooDeep()) return '';
  f = f.goDeeper();
  return choose(fuzzAlternation, fuzzGrouping, fuzzCharacterClass, fuzzRepetition, fuzzSequence)(f);
};


export default function fuzzRegExpPattern(f = {rng: new Random(Math.random)}) {
  let rv = fuzzRegExpSource(new RegExpState({rng: f.rng}));
  if (rv === '') return '(?:)';
  return rv;
}
