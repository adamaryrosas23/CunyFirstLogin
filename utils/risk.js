function geoScore(current, last) {
  if (!last || !last.country) return 0;

  let score = 0;
  if (current.country !== last.country) score += 70;
  if (current.region !== last.region) score += 20;
  if (current.city !== last.city) score += 10;
  return score;
}

function geoRiskLevel(score) {
  if (score >= 70) return "high";
  if (score >= 20) return "medium";
  return "low";
}

function fingerprintMatch(stored, current) {
  if (!stored) return true;
  return stored === current;
}

function decideMFA({ geoRisk, geoScoreValue, fpMatch, otpOnly }) {
  if (otpOnly) return true;
  if (!fpMatch) return true;
  if (geoRisk === "high") return true;
  if (geoScoreValue >= 70) return true;
  return false;
}

module.exports = { geoScore, geoRiskLevel, fingerprintMatch, decideMFA };
