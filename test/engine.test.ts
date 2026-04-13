import { describe, it, expect } from 'bun:test'
import { redactWithMatches } from '../src/engine'
import { PlaceholderSession } from '../src/session'
import type { GitleaksFinding } from '../src/detector'

describe('redactWithMatches', () => {
    it('returns original text when no findings', () => {
        const session = new PlaceholderSession()
        const result = redactWithMatches('hello world', session, [])
        expect(result.text).toBe('hello world')
        expect(result.matches).toHaveLength(0)
    })

    it('replaces single finding with placeholder', () => {
        const session = new PlaceholderSession()
        const text = 'token sk-1234567890abcdef secret'
        const findings: GitleaksFinding[] = [
            {
                start: 6,
                end: 26,
                original: 'sk-1234567890abcdef',
                category: 'generic-api-key',
                secret: 'sk-1234567890abcdef',
            },
        ]
        const result = redactWithMatches(text, session, findings)
        expect(result.text).not.toContain('sk-1234567890abcdef')
        expect(result.matches).toHaveLength(1)
        expect(result.matches[0].placeholder).toMatch(
            /^__SC_GENERIC_API_KEY_[a-f0-9]{20}__$/
        )
    })

    it('handles multiple findings', () => {
        const session = new PlaceholderSession()
        const text = 'ghp_abcdefghij and AKIAIOSFODNN7'
        const findings: GitleaksFinding[] = [
            {
                start: 0,
                end: 12,
                original: 'ghp_abcdefghij',
                category: 'github-token',
                secret: 'ghp_abcdefghij',
            },
            {
                start: 17,
                end: 29,
                original: 'AKIAIOSFODNN7',
                category: 'aws-access-key',
                secret: 'AKIAIOSFODNN7',
            },
        ]
        const result = redactWithMatches(text, session, findings)
        expect(result.text).not.toContain('ghp_abcdefghij')
        expect(result.text).not.toContain('AKIAIOSFODNN7')
        expect(result.matches).toHaveLength(2)
    })

    it('replaces from right to left to preserve offsets', () => {
        const session = new PlaceholderSession()
        const text = 'secret1 here secret2 end'
        const findings: GitleaksFinding[] = [
            {
                start: 0,
                end: 7,
                original: 'secret1',
                category: 'secret',
                secret: 'secret1',
            },
            {
                start: 12,
                end: 19,
                original: 'secret2',
                category: 'secret',
                secret: 'secret2',
            },
        ]
        const result = redactWithMatches(text, session, findings)
        expect(result.text).toContain('__SC_SECRET_')
        expect(result.text).not.toContain('secret1')
        expect(result.text).not.toContain('secret2')
    })

    it('maps placeholder back to original via session', () => {
        const session = new PlaceholderSession()
        const text = 'my key is sk-12345678 here'
        const findings: GitleaksFinding[] = [
            {
                start: 10,
                end: 21,
                original: 'sk-12345678',
                category: 'openai-key',
                secret: 'sk-12345678',
            },
        ]
        const result = redactWithMatches(text, session, findings)
        const placeholder = result.matches[0].placeholder
        expect(placeholder).toMatch(/^__SC_OPENAI_KEY_[a-f0-9]{20}__$/)
        expect(session.lookup(placeholder)).toBe('sk-12345678')
    })

    it('produces correct text after redaction', () => {
        const session = new PlaceholderSession()
        const text = 'api key: sk-12345678 is here'
        const findings: GitleaksFinding[] = [
            {
                start: 9,
                end: 20,
                original: 'sk-12345678',
                category: 'api-key',
                secret: 'sk-12345678',
            },
        ]
        const result = redactWithMatches(text, session, findings)
        expect(result.text).toContain('__SC_API_KEY_')
        expect(result.text).not.toContain('sk-12345678')
        expect(result.text).toContain(' is here')
    })
})
