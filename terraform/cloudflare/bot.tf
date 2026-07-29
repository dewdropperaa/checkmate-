# -----------------------------------------------------------------------------
# Bot management (Free: Bot Fight Mode)
#
# Bot Fight Mode is a zone-wide on/off toggle. It cannot be limited to
# /signup, /checkout, or /scan on the Free plan, and custom rules cannot Skip
# it. That is acceptable here: those paths are the abuse magnets, and mild
# friction on other public pages is fine.
#
# INBOUND vs OUTBOUND (do not confuse later):
#   - Traffic TO checkmate.ma / api.checkmate.ma FROM the internet → through
#     this Cloudflare zone → Bot Fight Mode can challenge it.
#   - Outbound scans FROM our backend agents TO customer targets → leave our
#     origin toward the customer's site. They do NOT enter this zone as
#     inbound requests, so Bot Fight Mode on checkmate.ma does not block our
#     scanner tools. (Customer sites may have their own bot protections.)
#   - Dodo webhooks INTO /webhooks/dodo ARE inbound. If Bot Fight Mode or
#     custom challenges interfere with webhook delivery, disable fight_mode
#     temporarily or upgrade to Super Bot Fight Mode (Pro) for skip rules,
#     and keep verifying X-Dodo-Webhook-Secret in the app.
# -----------------------------------------------------------------------------

resource "cloudflare_bot_management" "this" {
  zone_id    = local.zone_id
  fight_mode = var.enable_bot_fight_mode

  # Provider often drifts on read-only / plan-gated attributes.
  lifecycle {
    ignore_changes = [
      auto_update_model,
      optimize_wordpress,
      sbfm_definitely_automated,
      sbfm_likely_automated,
      sbfm_static_resource_protection,
      sbfm_verified_bots,
      stale_zone_configuration,
      suppress_session_score,
      using_latest_model,
    ]
  }
}
