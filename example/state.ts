import { type Signal, signal } from '@preact/signals'
import { FrostDKG } from '../src/index.js'
import type { ParticipantState } from '../src/participant.js'

export interface DKGResult {
    threshold: number
    n: number
    participants: ParticipantState[]
    groupPublicKey: string
}

export function State (): {
    threshold: Signal<number>
    total: Signal<number>
    loading: Signal<boolean>
    result: Signal<DKGResult | null>
    error: Signal<string | null>
} {  // eslint-disable-line indent
    const state = {
        threshold: signal<number>(3),
        total: signal<number>(5),
        loading: signal<boolean>(false),
        result: signal<DKGResult | null>(null),
        error: signal<string | null>(null),
    }

    return state
}

State.setThreshold = function (state: ReturnType<typeof State>, value: number) {
    state.threshold.value = value
}

State.setTotal = function (state: ReturnType<typeof State>, value: number) {
    state.total.value = value
}

State.runDKG = async function (state: ReturnType<typeof State>) {
    // Validation
    if (state.threshold.value < 2) {
        state.error.value = 'Threshold must be at least 2'
        return
    }

    if (state.threshold.value > state.total.value) {
        state.error.value = 'Threshold cannot exceed total participants'
        return
    }

    state.error.value = null
    state.result.value = null
    state.loading.value = true

    try {
        const dkg = new FrostDKG(state.threshold.value, state.total.value)
        const res = await dkg.run()
        state.result.value = res
    } catch (err) {
        state.error.value = (err as Error).message
    } finally {
        state.loading.value = false
    }
}
