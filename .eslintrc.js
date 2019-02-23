module.exports = {
  env: {
    browser: true,
    commonjs: true,
    node: true
  },
  extends: ['eslint-config-digitalbazaar'],
  parserOptions: {
    ecmaVersion: 5
  },
  rules: {
    // overrides to support ES5, remove when updated to ES20xx
    'no-unused-vars': 'warn',
    'no-var': 'off',
    'object-shorthand': 'off',
    'prefer-const': 'off'
  }
};
