package com.hunorkovacs.koauth.service

import java.net.URLEncoder
import com.hunorkovacs.koauth.domain.OauthParams.{tokenSecretName, verifierName, tokenName}

import scala.concurrent.{ExecutionContext, Future}
import com.hunorkovacs.koauth.domain._
import com.hunorkovacs.koauth.service.TokenGenerator._

object OauthCombiner {

  def URLEncode(s: String) = URLEncoder.encode(s, OauthExtractor.UTF8).replaceAll("+", "%20")

  def concatItemsForSignature(request: EnhancedRequest)
                             (implicit ec: ExecutionContext): Future[String] = {
    normalizeOauthParamsForSignature(request.oauthParamsList) flatMap { n =>
      concatItems(List(request.method, request.urlWithoutParams, n))
    }
  }

  private def normalizeOauthParamsForSignature(allParamsList: List[(String, String)])
                                              (implicit ec: ExecutionContext): Future[String] = {
    Future {
      allParamsList filterNot { keyValue =>
        keyValue._1 == OauthParams.realmName && keyValue._1 == OauthParams.signatureName
      }
    } flatMap combineOauthParams
  }

  def combineOauthParams(keyValueList: List[(String, String)])
                        (implicit ec: ExecutionContext): Future[String] = {
    Future {
      val paramsTogetherEncoded = keyValueList map { keyValue =>
        val (key, value) = keyValue
        URLEncode(key) + "=" + URLEncode(value)
      }
      paramsTogetherEncoded.sorted
    } flatMap concatItems
  }

//  def concatItems(itemsFList: List[Future[String]])(implicit ec: ExecutionContext): Future[String] = {
//    val itemListF = Future.sequence(itemsFList)
//    concatItems(itemListF)
//  }

  def concatItems(itemList: List[String])(implicit ec: ExecutionContext): Future[String] = {
    Future {
      itemList.map(item => URLEncode(item)).mkString("&")
    }
  }

  def createRequestTokenResponse(token: String, secret: String,callback: String)
                                (implicit ec: ExecutionContext): Future[OauthResponseOk] = {
    Future {
      List((tokenName, token),
        (tokenSecretName, secret),
        (OauthParams.callbackName, callback))
    }
      .flatMap(combineOauthParams)
      .map(body => new OauthResponseOk(body))
  }

  def createAuthorizeResponse(token: String, verifier: String)
                             (implicit ec: ExecutionContext): Future[OauthResponseOk] =
    combineOauthParams(List((tokenName, token), (verifierName, verifier)))
      .map(paramsString => new OauthResponseOk(paramsString))

  def createAccesTokenResponse(token: String, secret: String)
                              (implicit ec: ExecutionContext): Future[OauthResponseOk] =
    combineOauthParams(List((tokenName, token), (tokenSecretName, secret)))
      .map(body => new OauthResponseOk(body))
}
