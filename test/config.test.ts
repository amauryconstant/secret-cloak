import { describe, it, expect, spyOn, beforeEach, afterEach } from 'bun:test'
import path from 'node:path'
import { getConfigCandidates, loadConfig } from '../src/config'

const mockBunFile = spyOn(Bun, 'file')

describe('getConfigCandidates', () => {
    const home = process.env.HOME ?? '/'
    const globalConfig = path.join(
        home,
        '.config',
        'opencode',
        'secret-cloak.config.json'
    )

    afterEach(() => {
        delete process.env.OPENCODE_SECRET_CLOAK_CONFIG
    })

    it('returns project-local candidates first without env var', () => {
        const candidates = getConfigCandidates('/project')
        expect(candidates[0]).toBe(
            path.join('/project', 'secret-cloak.config.json')
        )
        expect(candidates[1]).toBe(
            path.join('/project', '.opencode', 'secret-cloak.config.json')
        )
        expect(candidates[candidates.length - 1]).toBe(globalConfig)
    })

    it('returns env-specified path first when set', () => {
        process.env.OPENCODE_SECRET_CLOAK_CONFIG = '/custom/path/config.json'
        const candidates = getConfigCandidates('/project')
        expect(candidates[0]).toBe('/custom/path/config.json')
        expect(candidates[1]).toBe(
            path.join('/project', 'secret-cloak.config.json')
        )
    })

    it('includes global config last', () => {
        const candidates = getConfigCandidates('/project')
        expect(candidates).toContain(globalConfig)
    })

    it('resolves env path relative to directory', () => {
        process.env.OPENCODE_SECRET_CLOAK_CONFIG = 'relative/config.json'
        const candidates = getConfigCandidates('/project')
        expect(candidates[0]).toBe(
            path.resolve('/project', 'relative/config.json')
        )
    })
})

describe('loadConfig', () => {
    beforeEach(() => {
        mockBunFile.mockReset()
    })

    afterEach(() => {
        delete process.env.OPENCODE_SECRET_CLOAK_CONFIG
    })

    it('returns default config when no file exists', async () => {
        const projectConfigPath = path.join(
            '/project',
            'secret-cloak.config.json'
        )
        mockBunFile.mockImplementation((p: string) => {
            return {
                exists: () => Promise.resolve(p !== projectConfigPath),
                text: () => Promise.reject(new Error('not found')),
            } as any
        })
        const result = await loadConfig('/project')
        expect(result.enabled).toBe(false)
        expect(result.debug).toBe(false)
        expect(result.session.ttlMs).toBe(3600000)
        expect(result.session.maxSessions).toBe(1000)
        expect(result.session.maxMappings).toBe(100000)
        expect(result.gitleaks.path).toBe(null)
        expect(result.gitleaks.patterns.exclude).toEqual([])
        expect(result.loadedFrom).toBe('')
    })

    it('loads config from first existing file', async () => {
        const projectConfigPath = path.join(
            '/project',
            'secret-cloak.config.json'
        )
        mockBunFile.mockImplementation((p: string) => {
            return {
                exists: () => Promise.resolve(p === projectConfigPath),
                text: () =>
                    Promise.resolve(
                        JSON.stringify({ enabled: true, debug: true })
                    ),
            } as any
        })
        const result = await loadConfig('/project')
        expect(result.enabled).toBe(true)
        expect(result.debug).toBe(true)
        expect(result.loadedFrom).toContain('secret-cloak.config.json')
    })

    it('returns defaults when file is malformed JSON', async () => {
        const projectConfigPath = path.join(
            '/project',
            'secret-cloak.config.json'
        )
        mockBunFile.mockImplementation((p: string) => {
            return {
                exists: () => Promise.resolve(p === projectConfigPath),
                text: () => Promise.resolve('not valid json'),
            } as any
        })
        const result = await loadConfig('/project')
        expect(result.enabled).toBe(false)
        expect(result.debug).toBe(false)
    })

    it('applies defaults when config values are missing', async () => {
        const projectConfigPath = path.join(
            '/project',
            'secret-cloak.config.json'
        )
        mockBunFile.mockImplementation((p: string) => {
            return {
                exists: () => Promise.resolve(p === projectConfigPath),
                text: () => Promise.resolve('{}'),
            } as any
        })
        const result = await loadConfig('/project')
        expect(result.enabled).toBe(true)
        expect(result.debug).toBe(false)
        expect(result.gitleaks.path).toBe(null)
        expect(result.gitleaks.patterns.exclude).toEqual([])
    })

    it('coerces enabled and debug to booleans', async () => {
        const projectConfigPath = path.join(
            '/project',
            'secret-cloak.config.json'
        )
        mockBunFile.mockImplementation((p: string) => {
            return {
                exists: () => Promise.resolve(p === projectConfigPath),
                text: () =>
                    Promise.resolve(
                        JSON.stringify({ enabled: 'yes', debug: 1 })
                    ),
            } as any
        })
        const result = await loadConfig('/project')
        expect(result.enabled).toBe(true)
        expect(result.debug).toBe(true)
    })

    it('extracts gitleaks path and exclude list from config', async () => {
        const projectConfigPath = path.join(
            '/project',
            'secret-cloak.config.json'
        )
        mockBunFile.mockImplementation((p: string) => {
            return {
                exists: () => Promise.resolve(p === projectConfigPath),
                text: () =>
                    Promise.resolve(
                        JSON.stringify({
                            gitleaks: {
                                path: '/custom/gitleaks',
                                patterns: { exclude: ['rule1', 'rule2'] },
                            },
                        })
                    ),
            } as any
        })
        const result = await loadConfig('/project')
        expect(result.gitleaks.path).toBe('/custom/gitleaks')
        expect(result.gitleaks.patterns.exclude).toEqual(['rule1', 'rule2'])
    })

    it('defaults gitleaks exclude to empty array when not provided', async () => {
        const projectConfigPath = path.join(
            '/project',
            'secret-cloak.config.json'
        )
        mockBunFile.mockImplementation((p: string) => {
            return {
                exists: () => Promise.resolve(p === projectConfigPath),
                text: () => Promise.resolve('{}'),
            } as any
        })
        const result = await loadConfig('/project')
        expect(result.gitleaks.patterns.exclude).toEqual([])
    })
})
