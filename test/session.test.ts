import { describe, it, expect, beforeEach } from 'bun:test'
import { PlaceholderSession, getPlaceholderRegex } from '../src/session'

describe('PlaceholderSession', () => {
    let session: PlaceholderSession

    beforeEach(() => {
        session = new PlaceholderSession({
            ttlMs: 60 * 60 * 1000,
            maxMappings: 100,
        })
    })

    it('generates consistent placeholder for same original and category', () => {
        const ph1 = session.getOrCreatePlaceholder('my-secret-key', 'API_KEY')
        const ph2 = session.getOrCreatePlaceholder('my-secret-key', 'API_KEY')
        expect(ph1).toBe(ph2)
        expect(ph1).toMatch(/^__SC_API_KEY_[a-f0-9]{20}__$/)
    })

    it('different secrets get different placeholders', () => {
        const ph1 = session.getOrCreatePlaceholder('secret-1', 'API_KEY')
        const ph2 = session.getOrCreatePlaceholder('secret-2', 'API_KEY')
        expect(ph1).not.toBe(ph2)
    })

    it('same secret same category returns same placeholder', () => {
        const ph1 = session.getOrCreatePlaceholder('secret', 'API_KEY')
        const ph2 = session.getOrCreatePlaceholder('secret', 'API_KEY')
        expect(ph1).toBe(ph2)
    })

    it('lookup returns original from placeholder', () => {
        const original = 'sk-1234567890abcdef'
        const placeholder = session.getOrCreatePlaceholder(
            original,
            'OPENAI_KEY'
        )
        expect(session.lookup(placeholder)).toBe(original)
    })

    it('lookup returns undefined for unknown placeholder', () => {
        expect(session.lookup('__SC_UNKNOWN_hash12__')).toBeUndefined()
    })

    it('evicts oldest when maxMappings exceeded', () => {
        const session = new PlaceholderSession({
            maxMappings: 3,
            ttlMs: Infinity,
        })
        const s1 = session.getOrCreatePlaceholder('a', 'X')
        const s2 = session.getOrCreatePlaceholder('b', 'X')
        const s3 = session.getOrCreatePlaceholder('c', 'X')
        session.getOrCreatePlaceholder('d', 'X')

        expect(session.lookup(s1)).toBeUndefined()
        expect(session.lookup(s2)).toBe('b')
        expect(session.lookup(s3)).toBe('c')
    })

    it('sanitizes category names by removing non-alphanumeric chars', () => {
        const ph = session.getOrCreatePlaceholder('secret', 'my-api-key')
        expect(ph).toMatch(/^__SC_MY_API_KEY_[a-f0-9]{20}__$/)
    })

    it('sanitizes category names with special chars', () => {
        const ph = session.getOrCreatePlaceholder('secret', 'my-api-key!')
        expect(ph).toMatch(/^__SC_MY_API_KEY_[a-f0-9]{20}__$/)
    })

    it('handles empty category', () => {
        const ph = session.getOrCreatePlaceholder('secret', '')
        expect(ph).toMatch(/^__SC_TEXT_[a-f0-9]{20}__$/)
    })

    it('cleanup removes expired entries', () => {
        const shortTTL = new PlaceholderSession({ ttlMs: 50, maxMappings: 100 })
        const before = Date.now()
        shortTTL.getOrCreatePlaceholder('secret1', 'X')
        shortTTL.getOrCreatePlaceholder('secret2', 'X')
        expect(shortTTL.lookupReverse('secret1')).toBeDefined()
        shortTTL.cleanup(before + 200)
        expect(shortTTL.lookupReverse('secret1')).toBeUndefined()
        expect(shortTTL.lookupReverse('secret2')).toBeUndefined()
    })

    it('cleanup does not remove non-expired entries', () => {
        const shortTTL = new PlaceholderSession({
            ttlMs: 10000,
            maxMappings: 100,
        })
        const ph = shortTTL.getOrCreatePlaceholder('secret', 'X')
        expect(shortTTL.lookup(ph)).toBe('secret')
        shortTTL.cleanup(Date.now())
        expect(shortTTL.lookup(ph)).toBe('secret')
    })

    it('cleanup skips when ttlMs is zero or negative', () => {
        const noTTL = new PlaceholderSession({ ttlMs: 0, maxMappings: 100 })
        const ph = noTTL.getOrCreatePlaceholder('secret', 'X')
        noTTL.cleanup(Date.now() + 100000)
        expect(noTTL.lookup(ph)).toBe('secret')
    })

    it('destroy clears all internal maps', () => {
        const s = new PlaceholderSession({ maxMappings: 100 })
        const ph = s.getOrCreatePlaceholder('secret', 'X')
        s.destroy()
        expect(s.lookup(ph)).toBeUndefined()
        expect(s.lookupReverse('secret')).toBeUndefined()
    })

    it('lookupReverse returns placeholder from original', () => {
        const s = new PlaceholderSession({ maxMappings: 100 })
        const ph = s.getOrCreatePlaceholder('my-secret', 'KEY')
        expect(s.lookupReverse('my-secret')).toBe(ph)
    })

    it('lookupReverse returns undefined for unknown original', () => {
        const s = new PlaceholderSession({ maxMappings: 100 })
        expect(s.lookupReverse('unknown')).toBeUndefined()
    })
})

describe('getPlaceholderRegex', () => {
    it('matches valid placeholders', () => {
        const re = getPlaceholderRegex()
        const matches = '__SC_API_KEY_a1b2c3d4e5f612345678__'.match(re)
        expect(matches).toHaveLength(1)
    })

    it('matches placeholder with numeric suffix', () => {
        const re = getPlaceholderRegex()
        const matches = '__SC_API_KEY_a1b2c3d4e5f612345678_2__'.match(re)
        expect(matches).toHaveLength(1)
    })

    it('does not match non-placeholder strings', () => {
        const re = getPlaceholderRegex()
        expect('normal text'.match(re)).toBeNull()
    })
})
