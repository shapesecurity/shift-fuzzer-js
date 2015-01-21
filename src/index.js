/**
 * Copyright 2014 Shape Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License")
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import isValid from "shift-validator";
import * as Shift from "shift-ast";
import codeGen from "shift-codegen";

let identifierStart = "_$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
let identifierPart = identifierStart + "0123456789";

let MANY_BOUND = 5;
let MAX_IDENT_LENGTH = 15;
let MAX_STRING_LENGTH = 3;

class R {
  constructor(rng) {
    this.rng = rng;
  }

  nextBoolean() {
    return this.rng() * 2 > 1;
  }

  nextInt(bound) {
    return Math.floor(this.rng() * bound);
  }

  nextDouble() {
    return this.rng();
  }
}

function e(gen1, gen2) {
  return (rng, depth) => rng.nextBoolean() ? gen1(rng, depth) : gen2(rng, depth);
}


function ap(f, ...g1) {
  return (rng, depth) => new f(...(g1.map(g=>g(rng, depth - 1))));
}

function manyB(bound, gen) {
  return (rng, depth) => {
    if (depth <= 0) {
      return [];
    }
    let number = rng.nextInt(bound);
    let result = [];
    for (let i = 0; i < number; i++) {
      result.push(gen(rng, depth));
    }
    return result;
  };
}

function many(gen) {
  return manyB(MANY_BOUND, gen);
}

function many1(gen) {
  return (rng, depth) =>
    manyB(MANY_BOUND - 1, gen)(rng, depth).push(gen(rng, depth));
}

function op(gen) {
  return (rng, depth) => depth <= 0 || rng.nextBoolean() ? null : gen(rng, depth);
}

function choice(...arr) {
  return (rng, depth) => arr[rng.nextInt(arr.length)];
}

function among(...arr) {
  return (rng, depth) => {
    let n = rng.nextInt(arr.length);
    return arr[n](rng, depth);
  }
}

let genString = (rng, depth) => {
  let length = rng.nextInt(MAX_STRING_LENGTH);
  return Array.apply([], new Array(length)).map(()=>String.fromCharCode(rng.nextInt(127 - 20) + 20)).join('');
};

let genIdentifierString = (rng, depth) => {
  let result = "";
  result += identifierStart[rng.nextInt(identifierStart.length)];
  let length = rng.nextInt(MAX_IDENT_LENGTH);
  for (let i = 0; i < length; i++) {
    result += identifierPart[rng.nextInt(identifierPart.length)];
  }
  return result.toString();
};

function map(f1, f2) {
  return (...args) => f2(f1(...args));
}

let genRegExpString =
  map(genIdentifierString, (s => "/" + s + "/"));
let genNumber =
  (rng, depth) => Math.exp(rng.nextDouble());
let genFunctionBody =
  ap(Shift.FunctionBody, many(genDirective), many(genStatement));
let genIdentifier =
  ap(Shift.Identifier, genIdentifierString);
let genPropertyNameString =
  ap(Shift.PropertyName, () => "string", genString);
let genPropertyNameIdent =
  ap(Shift.PropertyName, () => "identifier", map(genIdentifier, x => x.name));
let genPropertyNameNumber =
  ap(Shift.PropertyName, () => "number", map(genNumber, x => x.toString()));
let genPropertyName =
  among(genPropertyNameString, genPropertyNameIdent, genPropertyNameNumber);
let genDataProperty =
  ap(Shift.DataProperty, genPropertyName, genExpression);
let genGetter =
  ap(Shift.Getter, genPropertyName, genFunctionBody);
let genSetter =
  ap(Shift.Setter, genPropertyName, genIdentifier, genFunctionBody);
let genObjectProperty =
  among(genDataProperty, genGetter, genSetter);
let genBlock =
  ap(Shift.Block, many(genStatement));
let genVariableDeclarator =
  ap(Shift.VariableDeclarator, genIdentifier, op(genExpression));
let genVariableDeclaration =
  ap(Shift.VariableDeclaration, choice("let", "var"), many1(genVariableDeclarator));
let genSwitchCase =
  ap(Shift.SwitchCase, genExpression, many(genStatement));
let genSwitchDefault =
  ap(Shift.SwitchDefault, many(genStatement));
let genCatchClause =
  ap(Shift.CatchClause, genIdentifier, genBlock);
let genUnknownDirective =
  ap(Shift.UnknownDirective, genString);
let genUseStrictDirective =
  ap(Shift.UseStrictDirective);
let genArrayExpression =
  ap(Shift.ArrayExpression, many(op(genExpression)));
let genAssignmentExpression =
  ap(Shift.AssignmentExpression, choice("=", "+=", "-=", "*=", "/=", "%=", "<<=", ">>=", ">>>=", "|=", "^=", "&="), genExpression, genExpression);
let genBinaryExpression =
  ap(Shift.BinaryExpression, choice("==", "!=", "===", "!==", "<", "<=", ">", ">=", "in", "instanceof", "<<", ">>", ">>>", "+", "-", "*", "/", "%", ",", "||", "&&", "|", "^", "&"), genExpression, genExpression);
let genCallExpression =
  ap(Shift.CallExpression, genExpression, many(genExpression));
let genComputedMemberExpression =
  ap(Shift.ComputedMemberExpression, genExpression, genExpression);
let genConditionalExpression =
  ap(Shift.ConditionalExpression, genExpression, genExpression, genExpression);
let genFunctionExpression =
  ap(Shift.FunctionExpression, op(genIdentifier), many(genIdentifier), genFunctionBody);
let genIdentifierExpression =
  ap(Shift.IdentifierExpression, genIdentifier);
let genLiteralBooleanExpression =
  ap(Shift.LiteralBooleanExpression, choice(true, false));
let genLiteralNullExpression =
  ap(Shift.LiteralNullExpression);
let genLiteralNumericExpression =
  ap(Shift.LiteralNumericExpression, genNumber);
let genLiteralInfinityExpression =
  ap(Shift.LiteralInfinityExpression);
let genLiteralRegExpExpression =
  ap(Shift.LiteralRegExpExpression, genRegExpString);
let genLiteralStringExpression =
  ap(Shift.LiteralStringExpression, genString);
let genNewExpression =
  ap(Shift.NewExpression, genExpression, many(genExpression));
let genObjectExpression =
  ap(Shift.ObjectExpression, many(genObjectProperty));
let genPostfixExpression =
  ap(Shift.PostfixExpression, genExpression, choice("++", "--"));
let genPrefixExpression =
  ap(Shift.PrefixExpression, choice("+", "-", "!", "~", "typeof", "void", "delete", "++", "--"), genExpression);
let genStaticMemberExpression =
  ap(Shift.StaticMemberExpression, genExpression, genIdentifier);
let genThisExpression =
  ap(Shift.ThisExpression);
let genBlockStatement =
  ap(Shift.BlockStatement, genBlock);
let genDebuggerStatement =
  ap(Shift.DebuggerStatement);
let genDoWhileStatement =
  ap(Shift.DoWhileStatement, genStatement, genExpression);
let genEmptyStatement =
  ap(Shift.EmptyStatement);
let genExpressionStatement =
  ap(Shift.ExpressionStatement, genExpression);
let genForInStatement =
  ap(Shift.ForInStatement, e(genVariableDeclaration, genExpression), genExpression, genStatement);
let genForStatement =
  ap(Shift.ForStatement, op(e(genVariableDeclaration, genExpression)), op(genExpression), op(genExpression), genStatement);
let genFunctionDeclaration =
  ap(Shift.FunctionDeclaration, genIdentifier, many(genIdentifier), genFunctionBody);
let genIfStatement =
  ap(Shift.IfStatement, genExpression, genStatement, op(genStatement));
let genSwitchStatement =
  ap(Shift.SwitchStatement, genExpression, many(genSwitchCase));
let genSwitchStatementWithDefault =
  ap(Shift.SwitchStatementWithDefault, genExpression, many(genSwitchCase), genSwitchDefault, many(genSwitchCase));
let genThrowStatement =
  ap(Shift.ThrowStatement, genExpression);
let genTryCatchStatement =
  ap(Shift.TryCatchStatement, genBlock, genCatchClause);
let genTryFinallyStatement =
  ap(Shift.TryFinallyStatement, genBlock, op(genCatchClause), genBlock);
let genVariableDeclarationStatement =
  ap(Shift.VariableDeclarationStatement, genVariableDeclaration);
let genWhileStatement =
  ap(Shift.WhileStatement, genExpression, genStatement);
let genWithStatement =
  ap(Shift.WithStatement, genExpression, genStatement);
let genScript =
  ap(Shift.Script, genFunctionBody);
let genExpressionList = among(
  genArrayExpression,
  genAssignmentExpression,
  genBinaryExpression,
  genCallExpression,
  genComputedMemberExpression,
  genConditionalExpression,
  genFunctionExpression,
  genIdentifierExpression,
  genLiteralBooleanExpression,
  genLiteralNullExpression,
  genLiteralNumericExpression,
  genLiteralInfinityExpression,
  genLiteralRegExpExpression,
  genLiteralStringExpression,
  genNewExpression,
  genObjectExpression,
  genPostfixExpression,
  genPrefixExpression,
  genStaticMemberExpression,
  genThisExpression);
let genZeroLengthExpressionList = among(
  genArrayExpression,
  genIdentifierExpression,
  genLiteralBooleanExpression,
  genLiteralNullExpression,
  genLiteralNumericExpression,
  genLiteralInfinityExpression,
  genLiteralRegExpExpression,
  genLiteralStringExpression,
  genThisExpression);
let genDirectiveList = among(
  genUnknownDirective,
  genUseStrictDirective);
let genStatementList = among(
  genBlockStatement,
  genDebuggerStatement,
  genDoWhileStatement,
  genEmptyStatement,
  genExpressionStatement,
  genForInStatement,
  genForStatement,
  genFunctionDeclaration,
  genIfStatement,
  genSwitchStatement,
  genSwitchStatementWithDefault,
  genThrowStatement,
  genTryCatchStatement,
  genTryFinallyStatement,
  genVariableDeclarationStatement,
  genWhileStatement,
  genWithStatement);

function genExpression(random, depth) {
  return (depth <= 0 ? genZeroLengthExpressionList : genExpressionList)(random, depth);
}

function genDirective(random, depth) {
  return genDirectiveList(random, depth);
}

function genStatement(random, depth) {
  return genStatementList(random, depth);
}

export function generateTree(rng, depth) {
  let r = new R(rng);
  do {
    let tree = genScript(r, depth);
    if (isValid(tree)) {
      return tree;
    }
  } while (true);
}

export function generate(rng, depth) {
  return codeGen(generateTree(rng, depth));
}
