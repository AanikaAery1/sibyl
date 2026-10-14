-- 0013 rules/v1 seed. GENERATED from rules/v1/defaults.yaml by
--   python -m sibyl_control.migrate rules-seed --write
-- Do not edit. A YAML change ships as a new migration that redefines this function
-- (applied migrations are immutable); tenants then re-seed origin='seed' AND
-- overridden=false rows.
CREATE OR REPLACE FUNCTION sibyl.rules_seed()
RETURNS TABLE (rules_source text, seed_version text, feature_set text, yaml_sha256 bytea,
               rules jsonb, scoring_canonical text)
LANGUAGE sql IMMUTABLE AS $fn$
  SELECT 'rules/v1'::text, '1.0.0'::text, 'features/v1'::text,
         decode('b35446829b5c790f0f026c2dd8c6747fe83eefa3ab2b06f00cffa4ce43b15fad', 'hex'),
         $rules$[
 {
  "code": "error_rate",
  "collapses_to_provider": false,
  "comparator": "above",
  "cooldown_s": 600,
  "horizon_s": 0,
  "hysteresis_in": 3,
  "hysteresis_out": 12,
  "kind": "detected",
  "metric": "error_rate",
  "min_samples": 20,
  "penalty": 40,
  "scope": "agent",
  "severity": "warning",
  "short_code": "R1",
  "thresholds": {
   "sli_family": "availability",
   "tiers": {
    "1": {
     "cap": 50,
     "cooldown_s": 300,
     "hysteresis_in": 2,
     "hysteresis_out": 18,
     "threshold": 0.05
    },
    "2": {
     "cap": 40,
     "cooldown_s": 600,
     "hysteresis_in": 3,
     "hysteresis_out": 12,
     "threshold": 0.1
    },
    "3": {
     "cap": 30,
     "cooldown_s": 900,
     "hysteresis_in": 3,
     "hysteresis_out": 6,
     "threshold": 0.2
    }
   }
  },
  "tier_applicability": [
   1,
   2,
   3
  ],
  "trend_windows": null,
  "what_to_do": "Error rate {value} over {window} exceeds {threshold}. Check provider status and recent deploys; the failover saga moves traffic to the next fallback step.",
  "window_s": 300
 },
 {
  "code": "p95_latency",
  "collapses_to_provider": false,
  "comparator": "above",
  "cooldown_s": 600,
  "horizon_s": 0,
  "hysteresis_in": 3,
  "hysteresis_out": 12,
  "kind": "detected",
  "metric": "latency_p95_ms",
  "min_samples": 20,
  "penalty": 25,
  "scope": "agent",
  "severity": "warning",
  "short_code": "R2",
  "thresholds": {
   "relative_threshold": 2,
   "sli_family": "latency",
   "threshold_by_model_class": {
    "large": 20000,
    "reasoning": 60000,
    "small": 5000
   },
   "tiers": {
    "1": {
     "cap": 30,
     "cooldown_s": 300,
     "hysteresis_in": 2,
     "hysteresis_out": 18
    },
    "2": {
     "cap": 25,
     "cooldown_s": 600,
     "hysteresis_in": 3,
     "hysteresis_out": 12
    },
    "3": {
     "cap": 20,
     "cooldown_s": 900,
     "hysteresis_in": 3,
     "hysteresis_out": 6
    }
   }
  },
  "tier_applicability": [
   1,
   2,
   3
  ],
  "trend_windows": null,
  "what_to_do": "p95 latency {value} ms exceeds {threshold} ms. Compare with the provider's status and the agent's baseline before failing over.",
  "window_s": 300
 },
 {
  "code": "consecutive_failures",
  "collapses_to_provider": false,
  "comparator": "count",
  "cooldown_s": 600,
  "horizon_s": 0,
  "hysteresis_in": 1,
  "hysteresis_out": 12,
  "kind": "detected",
  "metric": "consecutive_errors",
  "min_samples": 1,
  "penalty": 50,
  "scope": "agent",
  "severity": "warning",
  "short_code": "R3",
  "thresholds": {
   "sli_family": "availability",
   "tiers": {
    "1": {
     "cap": 60,
     "cooldown_s": 300,
     "hysteresis_in": 1,
     "hysteresis_out": 18,
     "threshold": 3
    },
    "2": {
     "cap": 50,
     "cooldown_s": 600,
     "hysteresis_in": 1,
     "hysteresis_out": 12,
     "threshold": 3
    },
    "3": {
     "cap": 40,
     "cooldown_s": 900,
     "hysteresis_in": 1,
     "hysteresis_out": 6,
     "threshold": 5
    }
   }
  },
  "tier_applicability": [
   1,
   2,
   3
  ],
  "trend_windows": null,
  "what_to_do": "{value} consecutive failed calls. The agent is failing hard; detected-failure failover applies on every tier.",
  "window_s": 60
 },
 {
  "code": "provider_status",
  "collapses_to_provider": true,
  "comparator": "ordinal",
  "cooldown_s": 300,
  "horizon_s": 0,
  "hysteresis_in": 1,
  "hysteresis_out": 6,
  "kind": "detected",
  "metric": "provider_status",
  "min_samples": 0,
  "penalty": 60,
  "scope": "provider",
  "severity": "critical",
  "short_code": "R4",
  "thresholds": {
   "detected_at": "major_outage",
   "leading_at": [
    "maintenance",
    "degraded_performance",
    "partial_outage"
   ],
   "sli_family": "budget_dependency",
   "tiers": {
    "1": {
     "cap": 60,
     "cooldown_s": 300,
     "hysteresis_in": 1,
     "hysteresis_out": 6
    },
    "2": {
     "cap": 60,
     "cooldown_s": 300,
     "hysteresis_in": 1,
     "hysteresis_out": 6
    },
    "3": {
     "cap": 60,
     "cooldown_s": 300,
     "hysteresis_in": 1,
     "hysteresis_out": 6
    }
   }
  },
  "tier_applicability": [
   1,
   2,
   3
  ],
  "trend_windows": null,
  "what_to_do": "Provider reports {value}. Affected agents are failed over in tier order; one provider incident collects the member alerts.",
  "window_s": 300
 },
 {
  "code": "budget_breach",
  "collapses_to_provider": false,
  "comparator": "above",
  "cooldown_s": 21600,
  "horizon_s": 0,
  "hysteresis_in": 1,
  "hysteresis_out": 1,
  "kind": "detected",
  "metric": "spend_ratio",
  "min_samples": 0,
  "penalty": 70,
  "scope": "agent",
  "severity": "warning",
  "short_code": "R5",
  "thresholds": {
   "sli_family": "budget_dependency",
   "tiers": {
    "1": {
     "cap": 70,
     "cooldown_s": 21600,
     "hysteresis_in": 1,
     "hysteresis_out": 1,
     "threshold": 1
    },
    "2": {
     "cap": 70,
     "cooldown_s": 21600,
     "hysteresis_in": 1,
     "hysteresis_out": 1,
     "threshold": 1
    },
    "3": {
     "cap": 70,
     "cooldown_s": 21600,
     "hysteresis_in": 1,
     "hysteresis_out": 1,
     "threshold": 1
    }
   }
  },
  "tier_applicability": [
   1,
   2,
   3
  ],
  "trend_windows": null,
  "what_to_do": "Monthly budget exhausted ({value} of plan). Throttle or raise the budget in the continuity plan.",
  "window_s": 3600
 },
 {
  "code": "refusal_share",
  "collapses_to_provider": false,
  "comparator": "above",
  "cooldown_s": 600,
  "horizon_s": 0,
  "hysteresis_in": 6,
  "hysteresis_out": 12,
  "kind": "detected",
  "metric": "finish_content_filter_ratio",
  "min_samples": 20,
  "penalty": 20,
  "scope": "agent",
  "severity": "warning",
  "short_code": "R6",
  "thresholds": {
   "sli_family": "output_quality",
   "tiers": {
    "1": {
     "cap": 25,
     "cooldown_s": 600,
     "hysteresis_in": 6,
     "hysteresis_out": 18,
     "threshold": 0.1
    },
    "2": {
     "cap": 20,
     "cooldown_s": 600,
     "hysteresis_in": 6,
     "hysteresis_out": 12,
     "threshold": 0.15
    },
    "3": {
     "cap": 15,
     "cooldown_s": 600,
     "hysteresis_in": 6,
     "hysteresis_out": 6,
     "threshold": 0.25
    }
   }
  },
  "tier_applicability": [
   1,
   2,
   3
  ],
  "trend_windows": null,
  "what_to_do": "Refusal share {value} exceeds {threshold}. Review recent prompt or model changes; silent degradation is gated here (R37).",
  "window_s": 300
 },
 {
  "code": "truncation_share",
  "collapses_to_provider": false,
  "comparator": "above",
  "cooldown_s": 600,
  "horizon_s": 0,
  "hysteresis_in": 6,
  "hysteresis_out": 12,
  "kind": "detected",
  "metric": "finish_length_ratio",
  "min_samples": 20,
  "penalty": 15,
  "scope": "agent",
  "severity": "warning",
  "short_code": "R7",
  "thresholds": {
   "sli_family": "output_quality",
   "tiers": {
    "1": {
     "cap": 20,
     "cooldown_s": 600,
     "hysteresis_in": 6,
     "hysteresis_out": 18,
     "threshold": 0.25
    },
    "2": {
     "cap": 15,
     "cooldown_s": 600,
     "hysteresis_in": 6,
     "hysteresis_out": 12,
     "threshold": 0.25
    },
    "3": {
     "cap": 12,
     "cooldown_s": 600,
     "hysteresis_in": 6,
     "hysteresis_out": 6,
     "threshold": 0.25
    }
   },
   "vs_baseline": 2
  },
  "tier_applicability": [
   1,
   2,
   3
  ],
  "trend_windows": null,
  "what_to_do": "Truncated responses at {value} (twice the baseline). Check max_tokens and context size.",
  "window_s": 300
 },
 {
  "code": "schema_fail_share",
  "collapses_to_provider": false,
  "comparator": "above",
  "cooldown_s": 600,
  "horizon_s": 0,
  "hysteresis_in": 6,
  "hysteresis_out": 12,
  "kind": "detected",
  "metric": "schema_validation_fail_ratio",
  "min_samples": 20,
  "penalty": 20,
  "scope": "agent",
  "severity": "warning",
  "short_code": "R8",
  "thresholds": {
   "sli_family": "output_quality",
   "tiers": {
    "1": {
     "cap": 25,
     "cooldown_s": 600,
     "hysteresis_in": 6,
     "hysteresis_out": 18,
     "threshold": 0.1
    },
    "2": {
     "cap": 20,
     "cooldown_s": 600,
     "hysteresis_in": 6,
     "hysteresis_out": 12,
     "threshold": 0.15
    },
    "3": {
     "cap": 15,
     "cooldown_s": 600,
     "hysteresis_in": 6,
     "hysteresis_out": 6,
     "threshold": 0.2
    }
   }
  },
  "tier_applicability": [
   1,
   2,
   3
  ],
  "trend_windows": null,
  "what_to_do": "Tool-call schema failures at {value}. A model or tool contract changed; consider handing off.",
  "window_s": 300
 },
 {
  "code": "heartbeat_missing",
  "collapses_to_provider": false,
  "comparator": "boolean",
  "cooldown_s": 600,
  "horizon_s": 0,
  "hysteresis_in": 1,
  "hysteresis_out": 3,
  "kind": "detected",
  "metric": "request_count",
  "min_samples": 0,
  "penalty": 20,
  "scope": "agent",
  "severity": "warning",
  "short_code": "R9",
  "thresholds": {
   "applies_when": "plan_declares_cadence",
   "silent_cadence_multiple": 2,
   "sli_family": "availability",
   "tiers": {
    "1": {
     "cap": 25,
     "cooldown_s": 600,
     "hysteresis_in": 1,
     "hysteresis_out": 3
    },
    "2": {
     "cap": 20,
     "cooldown_s": 600,
     "hysteresis_in": 1,
     "hysteresis_out": 3
    },
    "3": {
     "cap": 15,
     "cooldown_s": 600,
     "hysteresis_in": 1,
     "hysteresis_out": 3
    }
   }
  },
  "tier_applicability": [
   1,
   2,
   3
  ],
  "trend_windows": null,
  "what_to_do": "No traffic for twice the declared cadence. Check the caller and the gateway path.",
  "window_s": 300
 },
 {
  "code": "tool_loop",
  "collapses_to_provider": false,
  "comparator": "composite",
  "cooldown_s": 600,
  "horizon_s": 0,
  "hysteresis_in": 3,
  "hysteresis_out": 12,
  "kind": "detected",
  "metric": "tool_seq_repeat_ratio",
  "min_samples": 20,
  "penalty": 25,
  "scope": "agent",
  "severity": "warning",
  "short_code": null,
  "thresholds": {
   "sli_family": "task_completion",
   "task_steps_p95_vs_baseline": 3,
   "tiers": {
    "1": {
     "cap": 30,
     "cooldown_s": 600,
     "hysteresis_in": 2,
     "hysteresis_out": 18
    },
    "2": {
     "cap": 25,
     "cooldown_s": 600,
     "hysteresis_in": 3,
     "hysteresis_out": 12
    },
    "3": {
     "cap": 20,
     "cooldown_s": 600,
     "hysteresis_in": 3,
     "hysteresis_out": 6
    }
   },
   "tool_call_count_5m": 20,
   "tool_seq_repeat_ratio": 0.5
  },
  "tier_applicability": [
   1,
   2,
   3
  ],
  "trend_windows": null,
  "what_to_do": "The agent repeats the same tool sequence. Quarantine (tier 1: await approval) and inspect the latest task.",
  "window_s": 300
 },
 {
  "code": "quality_proxy",
  "collapses_to_provider": false,
  "comparator": "composite",
  "cooldown_s": 600,
  "horizon_s": 0,
  "hysteresis_in": 6,
  "hysteresis_out": 12,
  "kind": "detected",
  "metric": "quality_proxy",
  "min_samples": 20,
  "penalty": 20,
  "scope": "agent",
  "severity": "info",
  "short_code": null,
  "thresholds": {
   "components": [
    "refusal_share",
    "truncation_share",
    "schema_fail_share"
   ],
   "empty_output_ratio": 0.05,
   "score_only": true,
   "sli_family": "output_quality",
   "tiers": {
    "1": {
     "cap": 25,
     "cooldown_s": 600,
     "hysteresis_in": 6,
     "hysteresis_out": 18
    },
    "2": {
     "cap": 20,
     "cooldown_s": 600,
     "hysteresis_in": 6,
     "hysteresis_out": 12
    },
    "3": {
     "cap": 15,
     "cooldown_s": 600,
     "hysteresis_in": 6,
     "hysteresis_out": 6
    }
   }
  },
  "tier_applicability": [
   1,
   2,
   3
  ],
  "trend_windows": null,
  "what_to_do": "Output quality proxy degraded; see the refusal, truncation and schema factors.",
  "window_s": 300
 },
 {
  "code": "flapping",
  "collapses_to_provider": false,
  "comparator": "count",
  "cooldown_s": 900,
  "horizon_s": 0,
  "hysteresis_in": 1,
  "hysteresis_out": 1,
  "kind": "detected",
  "metric": "band_transitions",
  "min_samples": 0,
  "penalty": 0,
  "scope": "agent",
  "severity": "warning",
  "short_code": null,
  "thresholds": {
   "alert_only": true,
   "sli_family": "availability",
   "tiers": {
    "1": {
     "cap": 0,
     "cooldown_s": 1200,
     "hysteresis_in": 1,
     "hysteresis_out": 1
    },
    "2": {
     "cap": 0,
     "cooldown_s": 900,
     "hysteresis_in": 1,
     "hysteresis_out": 1
    },
    "3": {
     "cap": 0,
     "cooldown_s": 900,
     "hysteresis_in": 1,
     "hysteresis_out": 1
    }
   }
  },
  "tier_applicability": [
   1,
   2,
   3
  ],
  "trend_windows": null,
  "what_to_do": "The agent's health band or routing flapped within {window}. It is pinned (tiers 1-2 at the worse band, tier 3 at the better band) while the hold lasts; inspect the transition list before releasing the pin.",
  "window_s": 600
 },
 {
  "code": "error_trend",
  "collapses_to_provider": false,
  "comparator": "trend",
  "cooldown_s": 600,
  "horizon_s": 900,
  "hysteresis_in": 6,
  "hysteresis_out": 12,
  "kind": "leading",
  "metric": "error_rate",
  "min_samples": 20,
  "penalty": 15,
  "scope": "agent",
  "severity": "warning",
  "short_code": "L1",
  "thresholds": {
   "level_vs_detected_threshold": 0.5,
   "sli_family": "availability",
   "tiers": {
    "1": {
     "cap": 20,
     "cooldown_s": 600,
     "hysteresis_in": 6,
     "hysteresis_out": 18
    },
    "2": {
     "cap": 15,
     "cooldown_s": 600,
     "hysteresis_in": 6,
     "hysteresis_out": 12
    },
    "3": {
     "cap": 10,
     "cooldown_s": 600,
     "hysteresis_in": 12,
     "hysteresis_out": 6
    }
   }
  },
  "tier_applicability": [
   1,
   2,
   3
  ],
  "trend_windows": 3,
  "what_to_do": "Errors are rising toward the failure threshold. Prepare the fallback; tier 1 asks for approval.",
  "window_s": 900
 },
 {
  "code": "latency_trend",
  "collapses_to_provider": false,
  "comparator": "trend",
  "cooldown_s": 600,
  "horizon_s": 900,
  "hysteresis_in": 6,
  "hysteresis_out": 12,
  "kind": "leading",
  "metric": "latency_p95_ms",
  "min_samples": 20,
  "penalty": 10,
  "scope": "agent",
  "severity": "warning",
  "short_code": "L2",
  "thresholds": {
   "level_vs_detected_threshold": 0.8,
   "sli_family": "latency",
   "tiers": {
    "1": {
     "cap": 15,
     "cooldown_s": 600,
     "hysteresis_in": 6,
     "hysteresis_out": 18
    },
    "2": {
     "cap": 10,
     "cooldown_s": 600,
     "hysteresis_in": 6,
     "hysteresis_out": 12
    },
    "3": {
     "cap": 8,
     "cooldown_s": 600,
     "hysteresis_in": 12,
     "hysteresis_out": 6
    }
   },
   "vs_baseline": 1.5
  },
  "tier_applicability": [
   1,
   2,
   3
  ],
  "trend_windows": 3,
  "what_to_do": "Latency is trending up toward its threshold.",
  "window_s": 900
 },
 {
  "code": "ratelimit_proximity",
  "collapses_to_provider": false,
  "comparator": "proximity",
  "cooldown_s": 600,
  "horizon_s": 900,
  "hysteresis_in": 6,
  "hysteresis_out": 12,
  "kind": "leading",
  "metric": "ratelimit_headroom",
  "min_samples": 5,
  "penalty": 20,
  "scope": "agent",
  "severity": "warning",
  "short_code": "L3",
  "thresholds": {
   "share_429": 0.05,
   "sli_family": "rate_limit_headroom",
   "tiers": {
    "1": {
     "cap": 25,
     "cooldown_s": 600,
     "hysteresis_in": 6,
     "hysteresis_out": 18,
     "threshold": 0.15
    },
    "2": {
     "cap": 20,
     "cooldown_s": 600,
     "hysteresis_in": 6,
     "hysteresis_out": 12,
     "threshold": 0.1
    },
    "3": {
     "cap": 15,
     "cooldown_s": 600,
     "hysteresis_in": 12,
     "hysteresis_out": 6,
     "threshold": 0.1
    }
   },
   "time_to_exhaustion_s": 900
  },
  "tier_applicability": [
   1,
   2,
   3
  ],
  "trend_windows": null,
  "what_to_do": "Rate-limit headroom is low. Throttle or spread traffic across fallback models.",
  "window_s": 300
 },
 {
  "code": "budget_proximity",
  "collapses_to_provider": false,
  "comparator": "proximity",
  "cooldown_s": 21600,
  "horizon_s": 3600,
  "hysteresis_in": 1,
  "hysteresis_out": 1,
  "kind": "leading",
  "metric": "budget_burn_1h",
  "min_samples": 0,
  "penalty": 15,
  "scope": "agent",
  "severity": "warning",
  "short_code": "L4",
  "thresholds": {
   "month_projected_24h": 1,
   "projected_1h": 0.9,
   "sli_family": "budget_dependency",
   "tiers": {
    "1": {
     "cap": 15,
     "cooldown_s": 21600,
     "hysteresis_in": 1,
     "hysteresis_out": 1
    },
    "2": {
     "cap": 15,
     "cooldown_s": 21600,
     "hysteresis_in": 1,
     "hysteresis_out": 1
    },
    "3": {
     "cap": 15,
     "cooldown_s": 21600,
     "hysteresis_in": 1,
     "hysteresis_out": 1
    }
   }
  },
  "tier_applicability": [
   1,
   2,
   3
  ],
  "trend_windows": null,
  "what_to_do": "Spend is projected to exhaust the budget. Throttle or raise the budget.",
  "window_s": 3600
 },
 {
  "code": "fallback_pressure",
  "collapses_to_provider": false,
  "comparator": "above",
  "cooldown_s": 600,
  "horizon_s": 900,
  "hysteresis_in": 6,
  "hysteresis_out": 12,
  "kind": "leading",
  "metric": "inline_fallback_breaker_share",
  "min_samples": 20,
  "penalty": 25,
  "scope": "agent",
  "severity": "warning",
  "short_code": "L5",
  "thresholds": {
   "sli_family": "rate_limit_headroom",
   "tiers": {
    "1": {
     "cap": 30,
     "cooldown_s": 600,
     "hysteresis_in": 6,
     "hysteresis_out": 18,
     "threshold": 0.1
    },
    "2": {
     "cap": 25,
     "cooldown_s": 600,
     "hysteresis_in": 6,
     "hysteresis_out": 12,
     "threshold": 0.2
    },
    "3": {
     "cap": 20,
     "cooldown_s": 600,
     "hysteresis_in": 12,
     "hysteresis_out": 6,
     "threshold": 0.25
    }
   }
  },
  "tier_applicability": [
   1,
   2,
   3
  ],
  "trend_windows": null,
  "what_to_do": "The gateway is leaning on inline fallback and open breakers. The primary is struggling.",
  "window_s": 300
 },
 {
  "code": "refusal_trend",
  "collapses_to_provider": false,
  "comparator": "trend",
  "cooldown_s": 600,
  "horizon_s": 900,
  "hysteresis_in": 6,
  "hysteresis_out": 12,
  "kind": "leading",
  "metric": "finish_content_filter_ratio",
  "min_samples": 20,
  "penalty": 10,
  "scope": "agent",
  "severity": "warning",
  "short_code": "L6",
  "thresholds": {
   "level_vs_detected_threshold": 0.5,
   "sli_family": "output_quality",
   "tiers": {
    "1": {
     "cap": 12,
     "cooldown_s": 600,
     "hysteresis_in": 6,
     "hysteresis_out": 18
    },
    "2": {
     "cap": 10,
     "cooldown_s": 600,
     "hysteresis_in": 6,
     "hysteresis_out": 12
    },
    "3": {
     "cap": 8,
     "cooldown_s": 600,
     "hysteresis_in": 12,
     "hysteresis_out": 6
    }
   }
  },
  "tier_applicability": [
   1,
   2,
   3
  ],
  "trend_windows": 3,
  "what_to_do": "Refusals are trending up. Review prompt and model changes before quality collapses.",
  "window_s": 900
 },
 {
  "code": "continuity_unverified",
  "collapses_to_provider": false,
  "comparator": "boolean",
  "cooldown_s": 86400,
  "horizon_s": 86400,
  "hysteresis_in": 1,
  "hysteresis_out": 1,
  "kind": "leading",
  "metric": "drill_overdue",
  "min_samples": 0,
  "penalty": 5,
  "scope": "agent",
  "severity": "warning",
  "short_code": "L7",
  "thresholds": {
   "sli_family": "budget_dependency",
   "tiers": {
    "1": {
     "cap": 5,
     "cooldown_s": 86400,
     "drill_overdue_days": 30,
     "hysteresis_in": 1,
     "hysteresis_out": 1
    },
    "2": {
     "cap": 5,
     "cooldown_s": 86400,
     "drill_overdue_days": 90,
     "hysteresis_in": 1,
     "hysteresis_out": 1
    },
    "3": {
     "cap": 0,
     "cooldown_s": 86400,
     "drill_overdue_days": 0,
     "hysteresis_in": 1,
     "hysteresis_out": 1
    }
   }
  },
  "tier_applicability": [
   1,
   2
  ],
  "trend_windows": null,
  "what_to_do": "The fallback has not been proven by a failover or drill recently. Schedule a drill.",
  "window_s": 86400
 },
 {
  "code": "context_saturation",
  "collapses_to_provider": false,
  "comparator": "above",
  "cooldown_s": 600,
  "horizon_s": 900,
  "hysteresis_in": 6,
  "hysteresis_out": 12,
  "kind": "leading",
  "metric": "context_utilisation_p95",
  "min_samples": 20,
  "penalty": 12,
  "scope": "agent",
  "severity": "warning",
  "short_code": null,
  "thresholds": {
   "finish_length_ratio": 0.25,
   "sli_family": "output_quality",
   "tiers": {
    "1": {
     "cap": 15,
     "cooldown_s": 600,
     "hysteresis_in": 6,
     "hysteresis_out": 18,
     "threshold": 0.85
    },
    "2": {
     "cap": 12,
     "cooldown_s": 600,
     "hysteresis_in": 6,
     "hysteresis_out": 12,
     "threshold": 0.85
    },
    "3": {
     "cap": 10,
     "cooldown_s": 600,
     "hysteresis_in": 12,
     "hysteresis_out": 6,
     "threshold": 0.85
    }
   }
  },
  "tier_applicability": [
   1,
   2,
   3
  ],
  "trend_windows": null,
  "what_to_do": "Context window nearly full. Trim context or move to a larger-context model.",
  "window_s": 300
 },
 {
  "code": "credential_expiry",
  "collapses_to_provider": false,
  "comparator": "below",
  "cooldown_s": 86400,
  "horizon_s": 86400,
  "hysteresis_in": 1,
  "hysteresis_out": 1,
  "kind": "leading",
  "metric": "days_to_credential_expiry",
  "min_samples": 0,
  "penalty": 15,
  "scope": "agent",
  "severity": "warning",
  "short_code": null,
  "thresholds": {
   "full_at": 1,
   "sli_family": "budget_dependency",
   "tiers": {
    "1": {
     "cap": 20,
     "cooldown_s": 86400,
     "hysteresis_in": 1,
     "hysteresis_out": 1,
     "threshold": 7
    },
    "2": {
     "cap": 15,
     "cooldown_s": 86400,
     "hysteresis_in": 1,
     "hysteresis_out": 1,
     "threshold": 7
    },
    "3": {
     "cap": 10,
     "cooldown_s": 86400,
     "hysteresis_in": 1,
     "hysteresis_out": 1,
     "threshold": 7
    }
   }
  },
  "tier_applicability": [
   1,
   2,
   3
  ],
  "trend_windows": null,
  "what_to_do": "A fallback credential expires soon. Rotate it before a failover needs it.",
  "window_s": 86400
 },
 {
  "code": "model_deprecation",
  "collapses_to_provider": false,
  "comparator": "below",
  "cooldown_s": 86400,
  "horizon_s": 86400,
  "hysteresis_in": 1,
  "hysteresis_out": 1,
  "kind": "leading",
  "metric": "days_to_model_deprecation",
  "min_samples": 0,
  "penalty": 10,
  "scope": "agent",
  "severity": "warning",
  "short_code": null,
  "thresholds": {
   "full_at": 7,
   "sli_family": "budget_dependency",
   "tiers": {
    "1": {
     "cap": 15,
     "cooldown_s": 86400,
     "hysteresis_in": 1,
     "hysteresis_out": 1,
     "threshold": 30
    },
    "2": {
     "cap": 10,
     "cooldown_s": 86400,
     "hysteresis_in": 1,
     "hysteresis_out": 1,
     "threshold": 30
    },
    "3": {
     "cap": 5,
     "cooldown_s": 86400,
     "hysteresis_in": 1,
     "hysteresis_out": 1,
     "threshold": 30
    }
   }
  },
  "tier_applicability": [
   1,
   2,
   3
  ],
  "trend_windows": null,
  "what_to_do": "The primary model is scheduled for deprecation. Plan a version change.",
  "window_s": 86400
 },
 {
  "code": "drift_cusum",
  "collapses_to_provider": false,
  "comparator": "trend",
  "cooldown_s": 3600,
  "horizon_s": 3600,
  "hysteresis_in": 6,
  "hysteresis_out": 18,
  "kind": "leading",
  "metric": "cusum_output",
  "min_samples": 20,
  "penalty": 0,
  "scope": "agent",
  "severity": "info",
  "short_code": null,
  "thresholds": {
   "features": [
    "tokens_out_mean",
    "output_chars_mean",
    "tool_seq_entropy"
   ],
   "sli_family": "output_quality",
   "tiers": {
    "1": {
     "cap": 0,
     "cooldown_s": 3600,
     "hysteresis_in": 6,
     "hysteresis_out": 18
    },
    "2": {
     "cap": 0,
     "cooldown_s": 3600,
     "hysteresis_in": 6,
     "hysteresis_out": 18
    },
    "3": {
     "cap": 0,
     "cooldown_s": 3600,
     "hysteresis_in": 6,
     "hysteresis_out": 18
    }
   },
   "watch_only": true
  },
  "tier_applicability": [
   1,
   2,
   3
  ],
  "trend_windows": null,
  "what_to_do": "Output distribution drifted with nothing else firing. Watch only.",
  "window_s": 3600
 }
]$rules$::jsonb,
         $scoring${"automation":{"min_confidence":"medium","min_rule_families":2,"predicted_failover_min_band_tiers_2_3":"0.90","release_candidate_band":"0.60","release_precision_floor":0.75,"release_recall_floor":0.6,"tier2_degrade_pause_s":20},"bands":{"1":{"degraded":45,"healthy":85,"watch":70},"2":{"degraded":40,"healthy":80,"watch":65},"3":{"degraded":30,"healthy":75,"watch":55}},"caps":{"budget_breach":{"1":70,"2":70,"3":70},"budget_proximity":{"1":15,"2":15,"3":15},"consecutive_failures":{"1":60,"2":50,"3":40},"context_saturation":{"1":15,"2":12,"3":10},"continuity_unverified":{"1":5,"2":5,"3":0},"credential_expiry":{"1":20,"2":15,"3":10},"drift_cusum":{"1":0,"2":0,"3":0},"error_rate":{"1":50,"2":40,"3":30},"error_trend":{"1":20,"2":15,"3":10},"fallback_pressure":{"1":30,"2":25,"3":20},"flapping":{"1":0,"2":0,"3":0},"heartbeat_missing":{"1":25,"2":20,"3":15},"latency_trend":{"1":15,"2":10,"3":8},"model_deprecation":{"1":15,"2":10,"3":5},"p95_latency":{"1":30,"2":25,"3":20},"provider_status":{"1":60,"2":60,"3":60},"quality_proxy":{"1":25,"2":20,"3":15},"ratelimit_proximity":{"1":25,"2":20,"3":15},"refusal_share":{"1":25,"2":20,"3":15},"refusal_trend":{"1":12,"2":10,"3":8},"schema_fail_share":{"1":25,"2":20,"3":15},"tool_loop":{"1":30,"2":25,"3":20},"truncation_share":{"1":20,"2":15,"3":12}},"carry_over":{"degraded_band_risk":0.4,"failed_band_risk":1},"dead_band":4,"failback_canary_pct":[10,25,50,100],"false_failover_budget_30d":[0,1,2],"feature_set":"features/v1","flap":{"band_transitions":3,"pin_direction":["worse","worse","better"],"pin_s":[1200,900,900],"routing_transitions":2,"window_s":600},"floors":{"error_rate_failed":0.5},"hysteresis_ticks":{"improve":[18,12,6],"worsen_detected":[2,3,3],"worsen_leading":[6,6,12]},"probability_band_cuts":{"band_0_25":0.15,"band_0_60":0.45,"band_0_90":0.8},"provisional":{"max_band":"watch","min_age_days":1,"min_coverage":0.8,"min_requests_1h":50},"rollup_lag_leading_refusal_s":120,"rules_source":"rules/v1","score":"clamp(100 - sum(cap(tier) * severity), 0, 100)","seed_baselines":{"error_rate":0.01,"p95_latency_ms":{"large":4000,"reasoning":15000,"small":1200}},"seed_version":"1.0.0","severity_curves":{"latency_saturation_multiple":2,"provider_status_ordinal":{"degraded_performance":0.33,"maintenance":0.15,"major_outage":1,"partial_outage":0.58,"unknown":0},"rate_saturation_multiple":3,"relative_saturation":4,"relative_threshold":2},"slo_agent_minutes_pct":["99.5","99.0","98.0"],"tick_s":10,"trend":{"cusum_h":5,"cusum_k":0.5,"ewma_lambda":0.3,"slope_window_s":300,"slope_windows":3}}$scoring$::text
$fn$;
GRANT EXECUTE ON FUNCTION sibyl.rules_seed() TO sibyl_app, sibyl_worker;
