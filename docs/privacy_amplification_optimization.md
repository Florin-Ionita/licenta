# Cum să optimizezi pierderea de biți la privacy amplification

Context: la QBER = 2% (default-ul din proiect), pierzi ~30% din biți între
informația teoretică a Evei (`h₂(p) ≈ 14%`) și leakage-ul de Cascade
(`~16%`). Acest document listează pârghiile concrete pentru a reduce
această pierdere, ordonate după impact și efort.

Fișierele de interes:
- [qkd/reconciliation.py](../qkd/reconciliation.py) — privacy amplification
- [qkd/_cascade.c](../qkd/_cascade.c) — hot loop Cascade în C
- [qkd/_cascade.py](../qkd/_cascade.py) — wrapper ctypes
- [benchmarks/qber_sweep.py](../benchmarks/qber_sweep.py) — sweep teoretic vs. real

---

## Cele două componente pe care le poți ataca

```
biti_pierduti = ceil(n * h2(qber))  +  leaked_bits
                └─ Eve, teoretic ─┘    └─ Cascade overhead ─┘
                FUNDAMENTAL              IMPLEMENTARE
```

- **Partea Eve (`n · h₂(p)`)** e mărginită de Csiszár-Körner. Singurul mod
  de a o reduce e să **scazi QBER-ul** (sau să folosești finite-key
  analysis mai fină, vezi §3).
- **Partea Cascade (`leaked_bits`)** depinde de cum implementezi
  reconcilierea. Aici e cea mai multă marjă fără modificări fizice.

---

## 1. Scade QBER-ul (atacă partea Eve)

**Impact:** mare. De la 2% la 1% pierzi 17% în loc de 30%.

**Cum:**
- În simulare: setezi `qber=0.01` în [qkd/abstract_link.py:84](../qkd/abstract_link.py#L84)
  și [viz/runtime.py:45](../viz/runtime.py#L45). E "barat" de realismul pe care
  vrei să-l demonstrezi în teză — sub 1% începi să fii nerealist pentru
  fibră comercială.
- În real: detectori cu dark count mic, fibră scurtă, polarizare stabilă.

**Trade-off:** dacă vrei să demonstrezi robustețe la zgomot, nu setezi QBER
artificial mic. Mai degrabă păstrezi 2% ca scenariu nominal și arăți în
benchmarks ce se întâmplă la 1%, 3%, 5%.

---

## 2. Optimizează Cascade (atacă partea de leakage)

### 2a. Acordează mărimea blocului `k₁`

Cascade folosește `k₁ ≈ 0.73 / QBER` ca regulă empirică (Brassard-Salvail
1994). Dar Martínez-Mateo et al. 2015 arată că `k₁` optim depinde de QBER:

| QBER | `k₁` optim | `k₂` (pass 2) |
|---|---|---|
| 1% | 73 | 146 |
| 2% | 36 | 72 |
| 5% | 14 | 28 |

**Cum verifici ce folosești:** uită-te în [qkd/_cascade.c](../qkd/_cascade.c)
la calculul block size. Dacă e hard-codat sau folosește o euristică
simplistă, ajustarea poate scoate 1-3% din leakage.

**Impact:** mic-mediu (~5-10% reducere a leak-ului, deci ~1% din `n`).

### 2b. Crește numărul de pass-uri

Default-ul din [qkd/_cascade.py:132](../qkd/_cascade.py#L132) este
`passes=4`. Mai multe pass-uri prind mai multe erori reziduale dar costă
parități în plus.

**Sweet spot:** 4 pass-uri pentru QBER 1-5%, 6-8 pentru QBER mai mare.

**Impact:** mic. Și e cu dublu efect — mai puține erori reziduale dar mai
multe parități scurse. La QBER 2% probabil 4 e deja optim.

### 2c. Înlocuiește Cascade cu LDPC sau Polar codes

**Impact:** mare (~5-8% reducere a leakage-ului).

LDPC (Low-Density Parity-Check) codes ajung la ~1.02 × h₂(p), față de
1.05-1.15 × pentru Cascade. Polar codes (Arıkan 2009) sunt și mai aproape
de Shannon. Folosite în implementări comerciale (ID Quantique, Toshiba).

**Trade-off:** mult mai complex de implementat. Necesită construirea unei
matrici de paritate optimizate offline per QBER. Cascade rămâne cel mai
popular în literatura academică tocmai pentru că e simplu.

**Verdict pentru teză:** menționează în limitări, nu implementa.

### 2d. Cascade cu rate-adaptive blocks

Variantă: în loc de blocuri fixe per pass, ajustezi `kᵢ` în funcție de
erorile descoperite în pass-urile anterioare. Reduce leakage cu ~2-3%.

Vezi: Pacher et al., *Demystifying the information reconciliation
protocol Cascade* (2015), Section 5.

---

## 3. Folosește finite-key analysis în loc de asymptotic

**Impact:** depinde de `n`. La `n` mic ești penalizat în plus; la `n` mare
e neglijabil.

**Ideea:** formula `n · h₂(p)` e asimptotică. Pentru `n` finit ai nevoie
de termen de corecție (smooth min-entropy, finite-key bounds din
Tomamichel & Leverrier 2017). Pentru un proiect academic asta merge în
direcția **inversă** — adaugi termeni de siguranță, deci pierzi mai mulți
biți, nu mai puțini.

**Concluzia:** menționează doar dacă vrei rigurozitate teoretică, nu ca
optimizare.

---

## 4. Mărește lungimea blocurilor sifted (`n`)

**Impact:** indirect, mediu.

Formula curentă pierde și prin rotunjire la byte:
```python
secure_bytes = secure_bits // 8   # pierzi 0-7 biți per apel
```

Plus `math.ceil(n * h₂(qber))` mai pierde sub 1 bit per apel.

Dacă procesezi `n = 1000` biți la un apel, overhead-ul de rotunjire e
~0.7%. Dacă procesezi `n = 100 000`, e ~0.007%. Concatenează mai mulți
blocuri sifted înainte de a apela `privacy_amplification`.

**Verdict:** ușor, fă-l.

---

## 5. Toeplitz hashing în loc de SHAKE-128

**Impact:** zero pe lungimea cheii, dar câștigi argument teoretic.

SHAKE-128 e **computationally secure**, nu **information-theoretically
secure**. Pentru o demonstrație riguroasă de securitate necondiționată
(care e tot scopul QKD), ar trebui un **2-universal hash family** — în
practică, Toeplitz matrix hashing (Krawczyk 1994).

**Trade-off:** mai lent (matmul cu matrice Toeplitz, ~O(n log n) cu FFT).
Nu schimbă numărul de biți pierduți.

**Verdict pentru teză:** **da, merită menționat și/sau implementat**. E o
slăbiciune teoretică reală a implementării curente (vezi
[docs/reconciliation_citations.md §5](reconciliation_citations.md#5-privacy-amplification)).

---

## Recomandarea mea concretă pentru proiectul tău

Ordinea după ROI (impact / efort):

1. **Concatenează blocuri sifted înainte de privacy amplification** —
   ~0% pierdere prin rotunjire, modificare trivială. **Fă-l.**
2. **Verifică `k₁` în [_cascade.c](../qkd/_cascade.c)** că folosește
   `0.73/QBER`. Dacă nu, ajustează. Mediu efort, ~1-2% câștig.
3. **Adaugă o secțiune în teză** despre Toeplitz vs SHAKE și LDPC vs
   Cascade, ca limitări cunoscute. Zero cod, plus de rigurozitate.
4. **Benchmark cu QBER variabil** ([benchmarks/qber_sweep.py](../benchmarks/qber_sweep.py))
   — ai deja asta, fă o figură curată în teză cu Shannon limit vs. real.
5. **NU înlocui Cascade cu LDPC** — efort enorm, complică povestea tezei
   fără să adauge mult.

---

## Referințe

- Brassard & Salvail 1994 — Cascade original, formula `k₁ ≈ 0.73/QBER`.
- Martínez-Mateo et al. 2015 — eficiența Cascade, parametri optimi.
- Pacher et al. 2015 — rate-adaptive Cascade.
- Krawczyk 1994 — Toeplitz hashing pentru privacy amplification.
- Arıkan 2009 — Polar codes.
- Tomamichel & Leverrier 2017 — finite-key analysis QKD.
