import { type FunctionComponent, render } from 'preact'
import { useCallback } from 'preact/hooks'
import { html } from 'htm/preact'
import '@substrate-system/css-normalize'
import { State } from './state.js'
import Debug from '@substrate-system/debug'
const debug = Debug(import.meta.env.DEV)

const state = State()

const App: FunctionComponent = function () {
    debug('rendering...', state)
    function truncate (str: string) {
        if (!str) return 'N/A'
        if (str.length <= 80) return str
        return str.substring(0, 40) + '...' + str.substring(str.length - 40)
    }

    const setTotal = useCallback((ev:InputEvent) => {
        const input = ev.target as HTMLInputElement
        const n = parseInt(input.value)
        State.setTotal(state, n)
    }, [state])

    const setThreshold = useCallback((ev:InputEvent) => {
        const input = ev.target as HTMLInputElement
        const n = parseInt(input.value)
        State.setThreshold(state, n)
    }, [state])

    const run = useCallback((ev:MouseEvent) => {
        ev.preventDefault()
        State.runDKG(state)
    }, [state])

    return html`
        <div class="container">
            <h1>FROST DKG Demo</h1>
            <p class="subtitle">
                Flexible Round-Optimized Schnorr Threshold Distributed
                Key Generation
            </p>

            <div class="protocol-steps">
                <h2>How FROST DKG Works</h2>

                <ol>
                    <li>
                        <strong>Round 1: </strong>
                        Each participant generates a polynomial and
                        creates commitments
                    </li>
                    <li>
                        <strong>Round 2: </strong>
                        Participants compute shares for each other and
                        encrypt them
                    </li>
                    <li>
                        <strong>Round 3: </strong>
                        Shares are verified and the group key is computed
                    </li>
                </ol>

                <p>
                    The result is a threshold scheme where
                    any <strong>t</strong> participants can reconstruct the key,
                    but fewer cannot.
                </p>
            </div>

            <div class="controls">
                <div class="input-group">
                    <label for="threshold">
                        Threshold (t) - minimum participants needed:
                    </label>
                    <input
                        type="number"
                        id="threshold"
                        min="2"
                        max="10"
                        value=${state.threshold}
                        onInput=${setThreshold}
                    />
                </div>

                <div class="input-group">
                    <label for="total">Total Participants (n):</label>
                    <input
                        type="number"
                        id="total"
                        min="2"
                        max="10"
                        value=${state.total}
                        onInput=${setTotal}
                    />
                </div>

                <button onClick=${run} disabled=${state.loading}>
                    ${state.loading.value
                        ? html`Running DKG Protocol<span class="spinner"></span>`
                        : 'Run DKG Protocol'
                    }
                </button>
            </div>

            ${state.error.value && html`
                <div class="error">Error: ${state.error.value}</div>
            `}

            ${state.result.value && html`
                <div class="results">
                    <div class="section">
                        <h2>Protocol Result</h2>
                        <div class="info-box">
                            <strong>Configuration</strong>
                            <div>
                                Threshold:
                                <strong>${state.result.value.threshold}</strong>
                                of <strong>${state.result.value.n}</strong>
                                participants
                            </div>
                        </div>
                        <div class="info-box">
                            <strong>Group Public Key</strong>
                            <code>${state.result.value.groupPublicKey}</code>
                        </div>
                    </div>

                    <div class="section">
                        <h2>Participants</h2>
                        <div class="participant-grid">
                            ${state.result.value.participants.map(p => html`
                                <div class="participant-card">
                                    <h3>Participant ${p.id}</h3>
                                    <div class="field">
                                        <div class="field-label">Secret Share</div>
                                        <div class="field-value">
                                            ${truncate(p.secretShare || '')}
                                        </div>
                                    </div>
                                    <div class="field">
                                        <div class="field-label">
                                            Verification Share
                                        </div>
                                        <div class="field-value">
                                            ${truncate(p.verificationShare || '')}
                                        </div>
                                    </div>
                                    <div class="field">
                                        <div class="field-label">
                                            Group Public Key
                                        </div>
                                        <div class="field-value">
                                            ${truncate(p.publicKey)}
                                        </div>
                                    </div>
                                </div>
                            `)}
                        </div>
                    </div>
                </div>
            `}
        </div>
    `
}

render(html`<${App} />`, document.getElementById('root')!)
