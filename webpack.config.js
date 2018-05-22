const path = require('path');

module.exports = {
    mode: process.env.NODE_ENV || 'development',
    target: "node",
    entry: {
      "index": "./src/index.ts",
      "cli": "./src/cli.ts",
    },
    output: {
        filename: "[name].js",
        path: path.resolve(__dirname, 'dist')
    },
    // Enable sourcemaps for debugging webpack's output.
    devtool: "source-map",
    resolve: {
        // Add '.ts' and '.tsx' as a resolvable extension.
        extensions: [".ts", ".tsx", ".js", ".json"]
    },
    module: {
        rules: [
            // all files with a '.ts' or '.tsx' extension will be handled by 'ts-loader'
            {
              test: /\.tsx?$/,
              loader: "ts-loader",
              exclude: /node_modules/
            },
            // All output '.js' files will have any sourcemaps re-processed by 'source-map-loader'.
            { enforce: "pre", test: /\.js$/, loader: "source-map-loader" }
        ]
    }
}
