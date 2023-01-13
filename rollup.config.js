import tsc from '@rollup/plugin-typescript'
import css from 'rollup-plugin-import-css'
import json from '@rollup/plugin-json'
import terser from '@rollup/plugin-terser'
import replace from '@rollup/plugin-replace'
import resolve from '@rollup/plugin-node-resolve'
import commonJs from '@rollup/plugin-commonjs'

export default {
  input: 'src/entry.ts',
  output: { file: 'public/app.js', format: 'esm', sourcemap: true },
  plugins: [
    tsc(),
    resolve(),
    json(),
    commonJs(),
    css(),
    replace({
      'process.env.NODE_ENV': JSON.stringify('production')
    }),
    process.env.minify ? terser({format: {comments: false}}) : {},
  ]
}
