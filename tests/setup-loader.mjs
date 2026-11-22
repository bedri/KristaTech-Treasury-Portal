import { registerHooks } from 'node:module'
import fs from 'node:fs'
import { fileURLToPath, pathToFileURL } from 'node:url'
import path from 'node:path'

registerHooks({
  resolve(specifier, context, nextResolve) {
    try {
      return nextResolve(specifier, context)
    } catch (err) {
      if (
        (specifier.startsWith('./') || specifier.startsWith('../')) &&
        context.parentURL &&
        !path.extname(specifier)
      ) {
        const parentDir = path.dirname(fileURLToPath(context.parentURL))
        const tsCandidate = path.resolve(parentDir, `${specifier}.ts`)
        if (fs.existsSync(tsCandidate)) {
          return nextResolve(pathToFileURL(tsCandidate).href, context)
        }
      }
      throw err
    }
  }
})
