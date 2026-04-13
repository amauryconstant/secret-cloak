import { scanWithGitleaks } from './detector'
import type { GitleaksFinding, PlaceholderSession, PlannedMatch } from './types'

function subtractCovered(
    start: number,
    end: number,
    covered: { start: number; end: number }[]
): { start: number; end: number }[] {
    if (start >= end) return []
    const out: { start: number; end: number }[] = []
    let cur = start
    for (const c of covered) {
        if (c.end <= cur) continue
        if (c.start >= end) break
        if (c.start > cur) out.push({ start: cur, end: Math.min(c.start, end) })
        if (c.end >= end) {
            cur = end
            break
        }
        cur = Math.max(cur, c.end)
    }
    if (cur < end) out.push({ start: cur, end })
    return out
}

function insertCovered(
    covered: { start: number; end: number }[],
    span: { start: number; end: number }
): { start: number; end: number }[] {
    if (span.start >= span.end) return covered
    let i = 0
    for (; i < covered.length; i++) {
        if (covered[i].start > span.start) break
    }
    covered.splice(i, 0, span)
    if (covered.length <= 1) return covered

    const merged: { start: number; end: number }[] = []
    for (const c of covered) {
        const last = merged.at(-1)
        if (!last) {
            merged.push(c)
            continue
        }
        if (c.start <= last.end) {
            if (c.end > last.end) last.end = c.end
            continue
        }
        merged.push(c)
    }
    return merged
}

export async function redactWithGitleaks(
    text: string,
    session: PlaceholderSession,
    gitleaksPath?: string | null
): Promise<{ text: string; matches: PlannedMatch[] }> {
    if (!text) return { text, matches: [] }
    const findings = await scanWithGitleaks(text, gitleaksPath)
    return redactWithMatches(text, session, findings)
}

export function redactWithMatches(
    text: string,
    session: PlaceholderSession,
    findings: GitleaksFinding[]
): { text: string; matches: PlannedMatch[] } {
    if (!text || !findings.length) return { text, matches: [] }

    const sorted = [...findings].sort((a, b) => {
        if (a.start !== b.start) return a.start - b.start
        return b.end - a.end
    })

    const planned: PlannedMatch[] = []
    let covered: { start: number; end: number }[] = []

    for (const m of sorted) {
        const segments = subtractCovered(m.start, m.end, covered)
        for (const seg of segments) {
            if (seg.start < 0 || seg.end > text.length || seg.start >= seg.end)
                continue
            planned.push({
                start: seg.start,
                end: seg.end,
                original: text.slice(seg.start, seg.end),
                category: m.category,
                placeholder: session.getOrCreatePlaceholder(
                    text.slice(seg.start, seg.end),
                    m.category
                ),
            })
            covered = insertCovered(covered, seg)
        }
    }

    planned.sort((a, b) => b.start - a.start)

    let out = text
    for (const m of planned) {
        out = out.slice(0, m.start) + m.placeholder + out.slice(m.end)
    }

    return { text: out, matches: planned }
}
