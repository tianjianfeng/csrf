package controllers

import play.api._
import play.api.mvc._
import utils.GetAction
import utils.PostAction

object UserController extends Controller {

  def getUser(username: String) = GetAction {
    Ok(views.html.index("Your new application is ready."))
  }
  
  def createUser = PostAction {
    Ok(views.html.index("Your new application is ready."))
  }

}