let local = require('../');
let n = 0;
while (true) {
	let expression = local.fuzzLiteralRegExpExpression(new local.FuzzerState(), true);
	let flags = [
		expression.global ? 'g' : '',
		expression.ignoreCase ? 'i' : '',
		expression.multiline ? 'm' : '',
		expression.sticky ? 'y' : '',
		expression.unicode ? 'u' : ''
	].join('');
	try {
		RegExp(expression.pattern, flags);
	} catch (e) {
		console.log(`failure: /${expression.pattern}/${flags},\nerror: ${e.message}`);
		process.exit(0)
	}
	n++;
	if (n % 100000 === 0) {
		console.log(`${n} done`);
	}
}
