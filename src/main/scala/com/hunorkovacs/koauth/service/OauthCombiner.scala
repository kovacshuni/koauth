package com.hunorkovacs.koauth.service

import java.net.URLEncoder
import com.hunorkovacs.koauth.domain.OauthParams._

import scala.concurrent.{ExecutionContext, Future}
import com.hunorkovacs.koauth.domain._

object OauthCombiner {

  def urlEncode(s: String) = URLEncoder.encode(s, OauthExtractor.UTF8)
    .replaceAll("\\+", "%20")
    .replaceAll("\\*", "%2A")
    .replaceAll("%7E", "~")

  def concatItemsForSignature(request: EnhancedRequest)
                             (implicit ec: ExecutionContext): Future[String] = {
    for {
      encodedMethod <- Future(urlEncode(request.method))
      encodedUrl <- Future(urlEncode(request.urlWithoutParams.toLowerCase))
      params <- normalizeOauthParamsForSignature(request.oauthParamsList)
      result <- concat(List(encodedMethod, encodedUrl, params))
    } yield result
  }

  def normalizeOauthParamsForSignature(allParamsList: List[(String, String)])
                                      (implicit ec: ExecutionContext): Future[String] = {
    Future(allParamsList.filterNot(kv => kv._1 == realmName || kv._1 == signatureName))
      .flatMap(encodePairConcat)
  }

  def encodePairConcat(keyValueList: List[(String, String)])
                        (implicit ec: ExecutionContext): Future[String] = {
    Future {
      (keyValueList map { keyValue =>
        val (key, value) = keyValue
        urlEncode(key) + "=" + urlEncode(value)
      }).sorted
    } flatMap concat
  }

  def concat(itemList: List[String])(implicit ec: ExecutionContext): Future[String] =
    Future(itemList.mkString("&"))

  def createRequestTokenResponse(token: String, secret: String,callback: String)
                                (implicit ec: ExecutionContext): Future[OauthResponseOk] = {
    Future {
      List((tokenName, token),
        (tokenSecretName, secret),
        (OauthParams.callbackName, callback))
    }
      .flatMap(encodePairConcat)
      .map(body => new OauthResponseOk(body))
  }

  def createAuthorizeResponse(token: String, verifier: String)
                             (implicit ec: ExecutionContext): Future[OauthResponseOk] =
    encodePairConcat(List((tokenName, token), (verifierName, verifier)))
      .map(paramsString => new OauthResponseOk(paramsString))

  def createAccesTokenResponse(token: String, secret: String)
                              (implicit ec: ExecutionContext): Future[OauthResponseOk] =
    encodePairConcat(List((tokenName, token), (tokenSecretName, secret)))
      .map(body => new OauthResponseOk(body))
}
