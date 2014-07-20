package com.hunorkovacs.koauth.domain

trait Verification

trait VerificationNok extends Verification

case object VerificationOk extends Verification

case class VerificationUnsupported(message: String) extends VerificationNok

case class VerificationFailed(message: String) extends VerificationNok
