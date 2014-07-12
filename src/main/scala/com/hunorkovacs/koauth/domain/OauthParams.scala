package com.hunorkovacs.koauth.domain

case class OauthParams(params: Map[String, String])

object OauthParams {
  final val consumerKeyName = "oauth_consumer_key"
  final val consumerSecretName = "oauth_consumer_secret"
  final val tokenName = "oauth_token"
  final val tokenSecretName = "oauth_token_secret"
  final val signatureMethodName = "oauth_signature_method"
  final val signatureName = "oauth_signature"
  final val timestampName = "oauth_timestamp"
  final val nonceName = "oauth_nonce"
  final val versionName = "oauth_version"
  final val callbackName = "oauth_callback"
  final val callbackConfirmedName = "oauth_callback_confirmed"
  final val verifierName = "oauth_verifier"
  final val realmName = "realm"
  final val usernameName = "username"
  final val passwordName = "password"
}
