import { type FunctionComponent, render } from 'preact'
import { useCallback } from 'preact/hooks'
import { useComputed } from '@preact/signals'
import Debug from '@substrate-system/debug'
import { html } from 'htm/preact'
import '@substrate-system/copy-button'
import '@substrate-system/css-normalize'
import '@substrate-system/a11y'
import '@substrate-system/copy-button/css'
import { State } from './state.js'
import { signatureToHex } from '../src/util.js'
const debug = Debug(import.meta.env.DEV)
const NBSP = '\u00A0'
const NDASH = '\u2013'

const state = State()

const App:FunctionComponent = function () {
    debug('rendering...', state)

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

    const generateParticipant = useCallback(async (participantId:number) => {
        await State.generateShard(state, participantId)
    }, [state])

    const verifyProofs = useCallback(async () => {
        await State.verifyProofs(state)
    }, [state])

    const verifyShares = useCallback(async () => {
        await State.verifyShares(state)
    }, [state])

    const completeKeyGen = useCallback(async () => {
        await State.completeKeyGeneration(state)
    }, [state])

    const toggleParticipant = useCallback((participantId:string) => {
        State.toggleParticipant(state, participantId)
    }, [state])

    const setMessage = useCallback((ev:Event) => {
        const input = ev.target as HTMLTextAreaElement
        State.setMessage(state, input.value)
    }, [state])

    const signMessage = useCallback((ev:MouseEvent) => {
        ev.preventDefault()
        State.signMessage(state)
    }, [state])

    const groupPublicKey = useComputed<string|undefined>(() => {
        return state.result.value?.groupPublicKey.toHex()
    })

    const selectedCount = useComputed<number>(() => {
        return state.signing.value.selectedParticipants.size
    })

    const requiredCount = useComputed<number>(() => {
        return state.result.value?.threshold || 0
    })

    const canSign = useComputed<boolean>(() => {
        const count = selectedCount.value
        const required = requiredCount.value
        return (count >= required && !!state.signing.value.message)
    })

    const verificationResult = useComputed<null|boolean>(() => {
        return state.signing.value.verificationResult
    })
    const sig = useComputed(() => {
        return state.signing.value.signature
    })

    return html`
        <div class="container">
            <h1>FROST DKG Demo</h1>
            <p class="subtitle">
                Flexible Round-Optimized Schnorr Threshold Distributed
                Key Generation
            </p>

            ${state.error.value && html`
                <div class="error">Error: ${state.error.value}</div>
            `}

            <div class="two-column-layout">
                <div class="left-column">
                    <div class="protocol-steps">
                        <h2>How FROST DKG Works</h2>

                        <ol>
                            <li>
                                <strong>Round 1: </strong>
                                Each participant generates a polynomial and
                                creates commitments. A Schnorr proof is generated
                                to prove knowledge of the secret coefficient.
                            </li>
                            <li>
                                <strong>Round 2: </strong>
                                Participants compute secret shares for every other
                                participant by evaluating their polynomial at each
                                participant's identifier. These shares are then
                                encrypted and exchanged with all
                                other participants.
                            </li>
                            <li>
                                <strong>Round 3: </strong>
                                Each participant first verifies the Schnorr proofs
                                from all others, then decrypts and verifies the
                                shares they received using the commitments. If all
                                verifications pass, the group public key is
                                computed by combining all commitments.
                            </li>

                            <li>
                                <strong>Signatures: </strong>
                                Each participant computes their partial signature
                                share using their secret, their random nonces, a
                                Lagrange coefficient, and the challenge derived
                                from the message. The signature shares are then
                                combined by simple addition.
                            </li>
                        </ol>

                        <p>
                            The result is a threshold scheme where
                            any <strong>t</strong> participants can sign things,
                            but fewer cannot.
                        </p>
                    </div>

                    ${state.result.value ? html`
                        <div class="signing-section">
                            <h2>Threshold Signing</h2>
                            <p class="info-text">
                                Select at least ${state.result.value.threshold}
                                ${NBSP}participants to create a threshold signature.
                            </p>

                            <div class="participant-grid">
                                ${state.result.value.participants.map(p => html`
                                    <div class="participant-card ${state.signing.value.selectedParticipants.has(p.id) ? 'selected' : ''}">
                                        <label class="participant-label">
                                            <input
                                                type="checkbox"
                                                checked=${state.signing.value.selectedParticipants.has(p.id)}
                                                onChange=${() => toggleParticipant(p.id)}
                                            />
                                            <span class="participant-name">
                                                Machine ${p.id}
                                            </span>
                                        </label>
                                    </div>
                                `)}
                            </div>

                            <div class="selection-info">
                                Selected: ${selectedCount.value} / ${requiredCount.value} required
                            </div>

                            <div class="signing-controls">
                                <div class="form-group">
                                    <h3 for="message">Message to sign</h3>
                                    <textarea
                                        id="message"
                                        rows="3"
                                        placeholder="Enter your message here..."
                                        value=${state.signing.value.message}
                                        onInput=${setMessage}
                                    ></textarea>
                                </div>

                                <button
                                    onClick=${signMessage}
                                    disabled=${
                                        state.signing.value.signing || !canSign.value
                                    }
                                    class="sign-btn"
                                >
                                    Sign Message
                                </button>
                            </div>

                            ${sig.value && html`
                                <div class="signature-result">
                                    <div class="h3">
                                        <h3>Signature (hex)</h3>
                                        <copy-button
                                            payload="${signatureToHex(sig.value)}"
                                        ></copy-button>
                                    </div>
                                    <div class="signature-box">
                                        <code>${signatureToHex(sig.value)}</code>
                                    </div>

                                    ${verificationResult !== null && html`
                                        <div
                                            class="verification-result ${verificationResult ?
                                                'valid' :
                                                'invalid'
                                            }"
                                        >
                                            ${verificationResult.value ?
                                                '✓ Signature is VALID' :
                                                '✗ Signature is INVALID'
                                            }
                                        </div>
                                    `}
                                </div>
                            `}
                        </div>
                    ` : html`
                        <div class="signing-section disabled">
                            <h2>Threshold Signing</h2>
                            <p class="info-text">
                                Generate each machine's keys first.
                            </p>
                        </div>
                    `}
                </div>

                <div class="right-column">
                    <div class="controls">
                        <h2>Key Generation</h2>
                        <div class="input-group">
                            <label for="threshold">
                                Threshold (t) - minimum participants needed
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
                            <label for="total">Total Participants (n)</label>
                            <input
                                type="number"
                                id="total"
                                min="2"
                                max="10"
                                value=${state.total}
                                onInput=${setTotal}
                            />
                        </div>

                        <div class="info-box">
                            <div class="label-controls">
                                <h3>Group Public Key (hex encoded)</h3>
                                <copy-button
                                    payload="${groupPublicKey.value || '-'}"
                                >
                                </copy-button>
                            </div>
                            <code>${groupPublicKey.value || '-'}</code>
                        </div>

                        <h2>Machines</h2>
                        <p>
                            These are all separate machines.
                            They must coordinate to generate their IDs, which are
                            <code> BigInt</code>s from 1 ${NDASH} n.${NBSP}
                            A minimum of number of <code>t</code> can
                            collaborate to sign something.
                        </p>

                        <div class="machine-boxes">
                            ${state.participantBoxes.value.map(box => html`
                                <div class="machine-box ${box.generated ? 'generated' : ''}">
                                    <div class="machine-header">
                                        <h3>Machine ${box.id}</h3>
                                        ${box.generated && html`
                                            <span class="status-badge">✓ Generated</span>
                                        `}
                                    </div>

                                    <div class="shard-display">
                                        <h4>Local Secret (hex)</h4>
                                        <code class="shard-value">
                                            ${
                                                (box.participant?.coefficients?.[0]
                                                    .toString(16)
                                                    .padStart(64, '0')) ||
                                                '-'
                                            }
                                        </code>
                                    </div>
                                    <button
                                        onClick=${() => generateParticipant(box.id)}
                                        disabled=${box.generated || state.loading.value}
                                        class="generate-btn"
                                    >
                                        ${box.generated ?
                                            'Shard Generated' :
                                            'Generate Shard'
                                        }
                                    </button>
                                </div>
                            `)}
                        </div>

                        ${state.allGenerated.value && !state.result.value && html`
                            <div class="verification-controls">
                                <h2>Verification</h2>
                                <p>
                                    Verifying the proofs
                                </p>
                                <button
                                    onClick=${verifyProofs}
                                    disabled=${state.proofsVerified.value || state.loading.value}
                                    class="verify-btn"
                                >
                                    ${state.proofsVerified.value ? '✓ Proofs Verified' : 'Verify Schnorr Proofs'}
                                </button>

                                <button
                                    onClick=${verifyShares}
                                    disabled=${!state.proofsVerified.value || state.sharesVerified.value || state.loading.value}
                                    class="verify-btn"
                                >
                                    ${state.sharesVerified.value ? '✓ Shares Verified' : 'Verify Shares'}
                                </button>

                                <button
                                    onClick=${completeKeyGen}
                                    disabled=${!state.sharesVerified.value || state.loading.value}
                                    class="verify-btn complete-btn"
                                >
                                    Complete Key Generation
                                </button>
                            </div>
                        `}

                        ${state.loading.value && html`
                            <div class="loading-message">
                                Completing DKG protocol...
                            </div>
                        `}
                    </div>
                </div>
            </div>
        </div>
    `
}

render(html`<${App} />`, document.getElementById('root')!)
