module.exports = {
    env: {
        es6: true,
        jest: true,
        browser: true,
        es2021: true,
        node: true
    },

    extends: "standard",
    parserOptions: {
        ecmaVersion: "latest"
    },

    plugins: [
        "import",
        "node"
    ],

    globals: {
        __filename: "readonly",
        __stack: "readonly",
        __file: "readonly",
        __line: "readonly",
        __fili: "readonly",
        __ext: "readonly",
        __base: "readonly",
        __func: "readonly",
        __dirname: "readonly"
    },

    rules: {
        // "no-console": "error",
        "linebreak-style": ["error", "unix"],
        "import/no-unresolved": "error",
        "node/no-missing-require": "error",
        "no-labels": 0,
        "no-self-compare": 0,
        "no-sequences": 0,
        "no-return-assign": 0,
        "no-tabs": ["error", { allowIndentationTabs: true }],
        "camelcase": 0,
        "no-unused-vars": ["off"],
        "no-reserved-keys": 0,
        "n/handle-callback-error": 0,
        "new-cap": 0,
        "space-before-function-paren": 0,
        "spaced-comment": ["error", "always"],
        "eqeqeq": 0,
        "eol-last": ["error", "always"],
        "quote-props": ["error", "consistent-as-needed"],
        "indent": ["error", 4, { SwitchCase: 1 }],
        "quotes": ["error", "double"],
        "semi": ["error", "always"],
        "semi-style": ["error", "last"],
        "no-inner-declarations": 0
    }
};
