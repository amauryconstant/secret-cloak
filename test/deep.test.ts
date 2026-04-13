import { describe, it, expect } from 'bun:test'
import { restoreText, restoreDeep } from '../src/deep'
import { PlaceholderSession } from '../src/session'

describe('restoreText', () => {
    it('returns input unchanged when no placeholders', () => {
        const session = new PlaceholderSession()
        const result = restoreText('hello world', session)
        expect(result).toBe('hello world')
    })

    it('restores placeholder to original value', () => {
        const session = new PlaceholderSession()
        const placeholder = session.getOrCreatePlaceholder(
            'my-secret',
            'API_KEY'
        )
        const result = restoreText(`some text ${placeholder} more`, session)
        expect(result).toBe('some text my-secret more')
    })

    it('leaves unknown placeholders unchanged', () => {
        const session = new PlaceholderSession()
        const result = restoreText('__SC_UNKNOWN_hash12__', session)
        expect(result).toBe('__SC_UNKNOWN_hash12__')
    })

    it('handles multiple placeholders', () => {
        const session = new PlaceholderSession()
        const ph1 = session.getOrCreatePlaceholder('key1', 'K1')
        const ph2 = session.getOrCreatePlaceholder('key2', 'K2')
        const result = restoreText(`${ph1} and ${ph2}`, session)
        expect(result).toBe('key1 and key2')
    })
})

describe('restoreDeep', () => {
    it('restores placeholders in object string values', () => {
        const session = new PlaceholderSession()
        const ph = session.getOrCreatePlaceholder('secret-value', 'SECRET')
        const obj = { apiKey: ph, name: 'test' }
        restoreDeep(obj, session)
        expect(obj.apiKey).toBe('secret-value')
        expect(obj.name).toBe('test')
    })

    it('restores placeholders in nested objects', () => {
        const session = new PlaceholderSession()
        const ph = session.getOrCreatePlaceholder('nested-secret', 'NEST')
        const obj = { outer: { inner: ph } }
        restoreDeep(obj, session)
        expect(obj.outer.inner).toBe('nested-secret')
    })

    it('restores placeholders in arrays', () => {
        const session = new PlaceholderSession()
        const ph = session.getOrCreatePlaceholder('array-secret', 'ARR')
        const arr = [ph, 'normal', { key: ph }]
        restoreDeep(arr, session)
        expect(arr[0]).toBe('array-secret')
        expect(arr[1]).toBe('normal')
        expect((arr[2] as Record<string, unknown>).key).toBe('array-secret')
    })

    it('handles non-string values gracefully', () => {
        const session = new PlaceholderSession()
        const obj = { num: 123, bool: true, null: null }
        restoreDeep(obj, session)
        expect(obj.num).toBe(123)
        expect(obj.bool).toBe(true)
    })

    it('restores placeholders in deeply nested structures (3+ levels)', () => {
        const session = new PlaceholderSession()
        const ph = session.getOrCreatePlaceholder('deep-secret', 'DEEP')
        const obj = { level1: { level2: { level3: { secret: ph } } } }
        restoreDeep(obj, session)
        expect(obj.level1.level2.level3.secret).toBe('deep-secret')
    })

    it('handles circular references without infinite loop', () => {
        const session = new PlaceholderSession()
        const obj: Record<string, unknown> = { name: 'test' }
        obj.self = obj
        expect(() => restoreDeep(obj, session)).not.toThrow()
    })
})
