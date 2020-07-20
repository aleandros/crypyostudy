# Cryptostudy

This is mostly a set of scripts based from the excercises of the book "Practical Cryptography in Python".

*DO NOT USE THIS CODE FOR PRODUCTION IN ANY FORM*. Some examples are deliberately insecure for
educational porpuses.

## Mac Setup

Besides `pipenv install --dev --pre` (the `--pre` flag is for the `black` formatter),
you will need to install the followingi n order for `gmpy2` library to be compiled.

```
brew install gmp
brew install mpfr
brew install libmpc
```