/**
 * Calcul Weibull - Analyse de fiabilité
 * β (beta) : paramètre de forme (< 1 = défauts précoces, = 1 = aléatoire, > 1 = usure)
 * η (eta)  : paramètre d'échelle (durée caractéristique en heures)
 */

function weibullAnalysis(values, timestamps) {
  if (!values || values.length < 3) return null

  const n = values.length
  
  // Calcul des rangs médians (méthode de Bernard)
  const sorted = values.map((v, i) => ({ v, t: timestamps[i] })).sort((a, b) => a.v - b.v)
  const medianRanks = sorted.map((_, i) => (i + 1 - 0.3) / (n + 0.4))
  
  // Régression linéaire sur ln(ln(1/(1-F))) vs ln(x)
  const x = sorted.map(s => Math.log(s.v))
  const y = medianRanks.map(f => Math.log(Math.log(1 / (1 - f))))
  
  const xMean = x.reduce((a, b) => a + b, 0) / n
  const yMean = y.reduce((a, b) => a + b, 0) / n
  
  const ssxy = x.reduce((s, xi, i) => s + (xi - xMean) * (y[i] - yMean), 0)
  const ssxx = x.reduce((s, xi) => s + (xi - xMean) ** 2, 0)
  
  if (ssxx === 0) return null
  
  const beta = ssxy / ssxx
  const eta = Math.exp(-(yMean - beta * xMean) / beta)
  
  // MTTF (Mean Time To Failure)
  const gamma = gammaFunction(1 + 1 / beta)
  const mttf = eta * gamma
  
  // Fiabilité actuelle basée sur la dernière valeur
  const lastValue = values[values.length - 1]
  const reliability = Math.exp(-Math.pow(lastValue / eta, beta))
  
  // Durée de vie restante estimée (heures)
  const remainingLife = mttf * reliability
  
  // Probabilité de panne dans les 30 prochains jours
  const t30 = 30 * 24
  const failureProb30 = 1 - Math.exp(-Math.pow(t30 / eta, beta))

  return {
    beta: Number(beta.toFixed(3)),
    eta: Number(eta.toFixed(2)),
    mttf: Number(mttf.toFixed(1)),
    reliability: Number((reliability * 100).toFixed(1)),
    remainingLife: Number(remainingLife.toFixed(1)),
    failureProb30: Number((failureProb30 * 100).toFixed(1)),
    diagnosis: beta < 1 ? 'Défauts précoces' : beta < 1.5 ? 'Pannes aléatoires' : 'Usure progressive',
    riskLevel: reliability < 0.5 ? 'critical' : reliability < 0.8 ? 'warning' : 'ok'
  }
}

// Approximation de la fonction Gamma
function gammaFunction(n) {
  if (n < 0.5) return Math.PI / (Math.sin(Math.PI * n) * gammaFunction(1 - n))
  n -= 1
  let x = 0.99999999999980993
  const p = [676.5203681218851, -1259.1392167224028, 771.32342877765313,
    -176.61502916214059, 12.507343278686905, -0.13857109526572012,
    9.9843695780195716e-6, 1.5056327351493116e-7]
  for (let i = 0; i < 8; i++) x += p[i] / (n + i + 1)
  const t = n + 7.5
  return Math.sqrt(2 * Math.PI) * Math.pow(t, n + 0.5) * Math.exp(-t) * x
}

module.exports = { weibullAnalysis }
