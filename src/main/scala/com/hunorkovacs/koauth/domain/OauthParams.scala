package com.hunorkovacs.koauth.domain

import scala.collection.mutable

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
  final val verifierName = "oauth_verifier"
  final val realmName = "realm"
  final val usernameName = "username"
  final val passwordName = "password"
  final val AllOauthParamNames = List[String](
    consumerKeyName,
    consumerSecretName,
    tokenName,
    tokenSecretName,
    signatureMethodName,
    signatureName,
    timestampName,
    nonceName,
    versionName,
    callbackName,
    verifierName,
    realmName,
    usernameName,
    passwordName)
}

class OauthParamsBuilder {

  import OauthParams._

  val built = mutable.HashMap.empty[String, String]

  def withOauthParams(oauthParams: OauthParams): OauthParamsBuilder = {
    built ++= oauthParams.params
    this
  }

  def withParam(paramName: String, value: String): OauthParamsBuilder = {
    if (!AllOauthParamNames.contains(paramName))
      throw new IllegalArgumentException("Parameter name is not allowed.")
    built += ((paramName, value))
    this
  }

  def build(): OauthParams = {
    new OauthParams(built.toMap)
  }
}
