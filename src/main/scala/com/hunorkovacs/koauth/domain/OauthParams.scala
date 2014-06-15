package com.hunorkovacs.koauth.domain

import scala.collection.mutable

class OauthParams(val paramNamesValues: Map[String, String]) {

  import OauthParams._

  val consumerKey = paramNamesValues(consumerKeyName)
  val consumerSecret = paramNamesValues(consumerSecretName)
  val token = paramNamesValues(tokenName)
  val tokenSecret = paramNamesValues(tokenSecretName)
  val signatureMethod = paramNamesValues(signatureMethodName)
  val signature = paramNamesValues(signatureName)
  val timestamp = paramNamesValues(timestampName)
  val nonce = paramNamesValues(nonceName)
  val version = paramNamesValues(versionName)
  val callback = paramNamesValues(callbackName)
  val verifier = paramNamesValues(verifierName)
  val realm = paramNamesValues(realmName)
  val username = paramNamesValues(usernameName)
  val password = paramNamesValues(passwordName)

  override def toString =
    StringBuilder.newBuilder.append(s"consumerKey=$consumerKey, ")
      .append(s"consumerSecret=$consumerSecret, ")
      .append(s"token=$token, ")
      .append(s"tokenSecret=$tokenSecret, ")
      .append(s"signatureMethod=$signatureMethod,")
      .append(s"timestamp=$timestamp, ")
      .append(s"nonce=$nonce, ")
      .append(s"version=$version, ")
      .append(s"callback=$callback, ")
      .append(s"signature=$signature").toString()
}

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
  final val AllOauthParamNames = List[String](consumerKeyName,
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

  def apply(source: OauthParams): OauthParams = new OauthParams(buildMap(source))



  def buildMap(source: OauthParams): Map[String, String] = {
    Map((consumerKeyName, source.consumerKey),
      (consumerSecretName, source.consumerSecret)
    )
  }
}

class OauthParamsBuilder {

  import OauthParams._

  val built = mutable.HashMap.empty[String, String]

  def withOauthParams(oauthParams: OauthParams): OauthParamsBuilder = {
    val oldMap = OauthParams.buildMap(oauthParams)
    oldMap.foreach(e => built += ((e._1, e._2)))
    this
  }

  def withProperty(propertyName: String, value: String): OauthParamsBuilder = {
    if (!AllOauthParamNames.contains(propertyName))
      throw new IllegalArgumentException("No such OauthParams property.")
    built += ((propertyName, value))
    this
  }

  def build(): OauthParams = {
    new OauthParams(built.toMap)
  }
}
