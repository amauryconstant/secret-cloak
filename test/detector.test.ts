import { describe, it, expect, spyOn, beforeEach, afterEach } from 'bun:test'
import {
    scanWithGitleaks,
    findGitleaks,
    lineColToOffset,
    parseGitleaksOutput,
} from '../src/detector'
import { redactWithGitleaks } from '../src/engine'
import { PlaceholderSession } from '../src/session'

let mockSpawn: ReturnType<typeof spyOn>

describe('lineColToOffset', () => {
    it('handles Unix LF newlines', () => {
        const text = 'line1\nline2\nline3'
        expect(lineColToOffset(text, 1, 1)).toBe(0)
        expect(lineColToOffset(text, 1, 3)).toBe(2)
        expect(lineColToOffset(text, 2, 1)).toBe(6)
        expect(lineColToOffset(text, 2, 3)).toBe(8)
        expect(lineColToOffset(text, 3, 1)).toBe(12)
    })

    it('handles Windows CRLF newlines', () => {
        const text = 'line1\r\nline2\r\nline3'
        expect(lineColToOffset(text, 1, 1)).toBe(0)
        expect(lineColToOffset(text, 1, 3)).toBe(2)
        expect(lineColToOffset(text, 2, 1)).toBe(7)
        expect(lineColToOffset(text, 2, 3)).toBe(9)
        expect(lineColToOffset(text, 3, 1)).toBe(14)
    })

    it('handles mixed newlines', () => {
        const text = 'line1\r\nline2\nline3'
        expect(lineColToOffset(text, 1, 1)).toBe(0)
        expect(lineColToOffset(text, 2, 1)).toBe(7)
        expect(lineColToOffset(text, 3, 1)).toBe(13)
    })
})

describe('findGitleaks', () => {
    beforeEach(() => {
        mockSpawn = spyOn(Bun, 'spawn')
    })

    afterEach(() => {
        mockSpawn.mockRestore()
    })

    it('caches the result after first call', async () => {
        mockSpawn.mockImplementation(
            ([_cmd, ..._args]: [string, ...string[]], _options?: any) => {
                return {
                    exited: Promise.resolve(0),
                    stdout: {
                        text: () => Promise.resolve('/custom/path/gitleaks'),
                    },
                } as any
            }
        )

        const p = findGitleaks()
        await p

        mockSpawn.mockClear()

        await findGitleaks()

        expect(mockSpawn).not.toHaveBeenCalled()
    })
})

describe('scanWithGitleaks', () => {
    beforeEach(() => {
        mockSpawn = spyOn(Bun, 'spawn')
    })

    afterEach(() => {
        mockSpawn.mockRestore()
    })

    it('returns empty array when gitleaks path is null and findGitleaks finds nothing', async () => {
        mockSpawn.mockImplementation(
            ([_cmd, ..._args]: [string, ...string[]], _options?: any) => {
                return {
                    exited: Promise.resolve(0),
                    stdout: { text: () => Promise.resolve('') },
                    stdin: { write: () => {}, end: () => {} },
                } as any
            }
        )

        const result = await scanWithGitleaks('some text', null)
        expect(result).toEqual([])
    })

    it('returns empty array on spawn error', async () => {
        mockSpawn.mockImplementation(
            ([_cmd, ..._args]: [string, ...string[]], _options?: any) => {
                return {
                    exited: Promise.reject(new Error('ENOENT')),
                    stdout: { text: () => Promise.resolve('') },
                    stdin: { write: () => {}, end: () => {} },
                } as any
            }
        )

        const result = await scanWithGitleaks(
            'some text',
            '/nonexistent/gitleaks'
        )
        expect(result).toEqual([])
    })

    it('returns empty array when gitleaks exits with code 0', async () => {
        mockSpawn.mockImplementation(
            ([_cmd, ..._args]: [string, ...string[]], _options?: any) => {
                return {
                    exited: Promise.resolve(0),
                    stdout: { text: () => Promise.resolve('') },
                    stdin: { write: () => {}, end: () => {} },
                } as any
            }
        )

        const result = await scanWithGitleaks('some text', '/usr/bin/gitleaks')
        expect(result).toEqual([])
    })

    it('calls spawn with correct arguments when path is provided', async () => {
        mockSpawn.mockImplementation(
            ([_cmd, ..._args]: [string, ...string[]], _options?: any) => {
                return {
                    exited: Promise.resolve(1),
                    stdout: { text: () => Promise.resolve('') },
                    stdin: { write: () => {}, end: () => {} },
                } as any
            }
        )

        await scanWithGitleaks('some text', '/custom/gitleaks')

        expect(mockSpawn).toHaveBeenCalledWith(
            [
                '/custom/gitleaks',
                'stdin',
                '-r',
                '-',
                '-f',
                'json',
                '--redact=0',
                '--no-banner',
                '--log-level=warn',
            ],
            expect.objectContaining({ stdio: ['pipe', 'pipe', 'pipe'] })
        )
    })
})

describe('parseGitleaksOutput', () => {
    it('converts single finding line/col to offsets', () => {
        const text = 'line1\nline2\nline3'
        const json = JSON.stringify([
            {
                StartLine: 2,
                StartColumn: 1,
                EndLine: 2,
                EndColumn: 6,
                Match: 'secret',
                RuleID: 'generic-api-key',
                Secret: 'sk-secret',
            },
        ])
        const results = parseGitleaksOutput(json, text)
        expect(results).toHaveLength(1)
        expect(results[0]).toMatchObject({
            start: 6,
            end: 11,
            match: 'secret',
            category: 'generic-api-key',
            secret: 'sk-secret',
        })
    })

    it('converts multiple findings with correct offsets', () => {
        const text = 'api key: sk-1234567890abcdef'
        const json = JSON.stringify([
            {
                StartLine: 1,
                StartColumn: 10,
                EndLine: 1,
                EndColumn: 26,
                Match: 'sk-1234567890abcdef',
                RuleID: 'openai-key',
                Secret: 'sk-1234567890abcdef',
            },
        ])
        const results = parseGitleaksOutput(json, text)
        expect(results).toHaveLength(1)
        expect(results[0].start).toBe(9)
        expect(results[0].end).toBe(25)
    })

    it('handles findings with empty secret', () => {
        const text = 'some text'
        const json = JSON.stringify([
            {
                StartLine: 1,
                StartColumn: 6,
                EndLine: 1,
                EndColumn: 10,
                Match: 'test',
                RuleID: 'test-rule',
                Secret: '',
            },
        ])
        const results = parseGitleaksOutput(json, text)
        expect(results).toHaveLength(1)
        expect(results[0].secret).toBe('')
    })

    it('returns empty array when json is empty array', () => {
        const results = parseGitleaksOutput('[]', 'any text')
        expect(results).toHaveLength(0)
    })

    it('handles Windows CRLF newlines in text', () => {
        const text = 'line1\r\nline2\r\nline3'
        const json = JSON.stringify([
            {
                StartLine: 2,
                StartColumn: 1,
                EndLine: 2,
                EndColumn: 5,
                Match: 'test',
                RuleID: 'test',
                Secret: 'test',
            },
        ])
        const results = parseGitleaksOutput(json, text)
        expect(results).toHaveLength(1)
        expect(results[0].start).toBe(7)
        expect(results[0].end).toBe(11)
    })
})

describe('redactWithGitleaks', () => {
    beforeEach(() => {
        mockSpawn = spyOn(Bun, 'spawn')
    })

    afterEach(() => {
        mockSpawn.mockRestore()
    })

    it('returns empty result for empty string', async () => {
        const session = new PlaceholderSession()
        const result = await redactWithGitleaks('', session)
        expect(result.text).toBe('')
        expect(result.matches).toHaveLength(0)
    })

    it('returns unchanged text when no findings', async () => {
        const session = new PlaceholderSession()
        mockSpawn.mockImplementation(
            ([_cmd, ..._args]: [string, ...string[]], _options?: any) => {
                return {
                    exited: Promise.resolve(1),
                    stdout: { text: () => Promise.resolve('') },
                    stdin: { write: () => {}, end: () => {} },
                } as any
            }
        )
        const result = await redactWithGitleaks('hello world', session)
        expect(result.text).toBe('hello world')
        expect(result.matches).toHaveLength(0)
    })

    it('passes gitleaksPath as null when not provided', async () => {
        const session = new PlaceholderSession()
        mockSpawn.mockImplementation(
            ([_cmd, ..._args]: [string, ...string[]], _options?: any) => {
                return {
                    exited: Promise.resolve(1),
                    stdout: { text: () => Promise.resolve('') },
                    stdin: { write: () => {}, end: () => {} },
                } as any
            }
        )
        await redactWithGitleaks('some text', session)
        expect(mockSpawn).toHaveBeenCalledWith(
            expect.arrayContaining(['stdin', '-r', '-', '-f', 'json']),
            expect.any(Object)
        )
    })

    it('passes gitleaksPath when explicitly provided', async () => {
        const session = new PlaceholderSession()
        mockSpawn.mockImplementation(
            ([_cmd, ..._args]: [string, ...string[]], _options?: any) => {
                return {
                    exited: Promise.resolve(1),
                    stdout: { text: () => Promise.resolve('') },
                    stdin: { write: () => {}, end: () => {} },
                } as any
            }
        )
        await redactWithGitleaks('some text', session, '/custom/gitleaks')
        expect(mockSpawn).toHaveBeenCalledWith(
            expect.arrayContaining(['/custom/gitleaks']),
            expect.any(Object)
        )
    })
})

describe('scanWithGitleaks integration', () => {
    beforeEach(() => {
        mockSpawn = spyOn(Bun, 'spawn')
    })

    afterEach(() => {
        mockSpawn.mockRestore()
    })

    it('parses valid gitleaks JSON output and returns findings', async () => {
        mockSpawn.mockImplementation(
            ([_cmd, ..._args]: [string, ...string[]], _options?: any) => {
                return {
                    exited: Promise.resolve(0),
                    stdout: {
                        text: () =>
                            Promise.resolve(
                                JSON.stringify([
                                    {
                                        StartLine: 1,
                                        StartColumn: 10,
                                        EndLine: 1,
                                        EndColumn: 26,
                                        Match: 'sk-1234567890abcdef',
                                        RuleID: 'generic-api-key',
                                        Secret: 'sk-1234567890abcdef',
                                    },
                                ])
                            ),
                    },
                    stdin: { write: () => {}, end: () => {} },
                } as any
            }
        )

        const result = await scanWithGitleaks(
            'text with sk-1234567890abcdef secret',
            '/custom/gitleaks'
        )
        expect(result).toHaveLength(1)
        expect(result[0]).toMatchObject({
            category: 'generic-api-key',
            match: 'sk-1234567890abcdef',
            secret: 'sk-1234567890abcdef',
        })
        expect(typeof result[0].start).toBe('number')
        expect(typeof result[0].end).toBe('number')
    })

    it('filters findings by excluded categories', async () => {
        mockSpawn.mockImplementation(
            ([_cmd, ..._args]: [string, ...string[]], _options?: any) => {
                return {
                    exited: Promise.resolve(0),
                    stdout: {
                        text: () =>
                            Promise.resolve(
                                JSON.stringify([
                                    {
                                        StartLine: 1,
                                        StartColumn: 1,
                                        EndLine: 1,
                                        EndColumn: 10,
                                        Match: 'aws-key',
                                        RuleID: 'aws-access-key',
                                        Secret: 'AKIAIOSFODNN7EXAMPLED',
                                    },
                                    {
                                        StartLine: 1,
                                        StartColumn: 12,
                                        EndLine: 1,
                                        EndColumn: 22,
                                        Match: 'github-token',
                                        RuleID: 'github-token',
                                        Secret: 'ghp_example123456789',
                                    },
                                ])
                            ),
                    },
                    stdin: { write: () => {}, end: () => {} },
                } as any
            }
        )

        const result = await scanWithGitleaks(
            'AKIAIOSFODNN7EXAMPLED ghp_example123456789',
            '/custom/gitleaks',
            ['github-token']
        )
        expect(result).toHaveLength(1)
        expect(result[0].category).toBe('aws-access-key')
    })
})
