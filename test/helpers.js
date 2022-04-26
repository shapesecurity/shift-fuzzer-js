function testRepeatedly(desc, fn) {
  test(desc, () => {
    for (let i = 1e2; i > 0; --i) fn();
  });
}

const prng = (function(){
  let i = 0, l = 100;
  let randomNumbers = [];
  for (; i < l; ++i) randomNumbers.push(Math.random());
  function prng() {
    i = (i + 1) % l;
    return randomNumbers[i];
  };
  prng.reset = () => i = 0;
  return prng;
}());

module.exports = {
  testRepeatedly,
  prng,
};
