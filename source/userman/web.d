/**
	Web interface implementation

	Copyright: © 2012-2014 RejectedSoftware e.K.
	License: Subject to the terms of the General Public License version 3, as written in the included LICENSE.txt file.
	Authors: Sönke Ludwig
*/
module userman.web;

public import userman.db.controller;

import vibe.core.log;
import vibe.crypto.passwordhash;
import vibe.http.router;
import vibe.textfilter.urlencode;
import vibe.utils.validation;
import vibe.web.web;

import std.exception;


/**
	Registers the routes for a UserMan web interface.

	Use this to add user management to your web application. See also
	$(D UserManWebAuthenticator) for some complete examples of a simple
	web service with UserMan integration.
*/
void registerUserManWebInterface(URLRouter router, UserManController controller)
{
	router.registerWebInterface(new UserManWebInterface(controller));
}


/**
	Helper function to update the user profile from a POST request.

	This assumes that the fields are named like they are in userman.profile.dt.
	Session variables will be updated automatically.
*/
void updateProfile(UserManController controller, User user, HTTPServerRequest req)
{

	if (auto pv = "password" in req.form) {
		enforce(user.auth.method == "password", "User account has no password authentication.");
		auto pconf = "password_confirmation" in req.form;
		enforce(pconf !is null, "Missing password confirmation.");
		validatePassword(*pv, *pconf);
		user.auth.passwordHash = generateSimplePasswordHash(*pv);
	}

	controller.updateUser(user);

	req.session.set("userName", user.name);
}


/**
	Used to privide request authentication for web applications.
*/
class UserManWebAuthenticator {
	private {
		UserManController m_controller;
		string m_prefix;
	}

	this(UserManController controller, string prefix = "/")
	{
		m_controller = controller;
		m_prefix = prefix;
	}

	HTTPServerRequestDelegate auth(void delegate(HTTPServerRequest, HTTPServerResponse, User) callback)
	{
		void requestHandler(HTTPServerRequest req, HTTPServerResponse res)
		{
			User usr;
			try usr = performAuth(req, res);
			catch (Exception e) throw new HTTPStatusException(HTTPStatus.unauthorized);
			if (res.headerWritten) return;
			callback(req, res, usr);
		}
		
		return &requestHandler;
	}
	HTTPServerRequestDelegate auth(HTTPServerRequestDelegate callback)
	{
		return auth((req, res, user){ callback(req, res); });
	}

	User performAuth(HTTPServerRequest req, HTTPServerResponse res)
	{
		if (!req.session) {
			res.redirect(m_prefix~"login?redirect="~urlEncode(req.path));
			return User.init;
		} else {
			return m_controller.getUserByName(req.session.get!string("userName"));
		}
	}
	
	HTTPServerRequestDelegate ifAuth(void delegate(HTTPServerRequest, HTTPServerResponse, User) callback)
	{
		void requestHandler(HTTPServerRequest req, HTTPServerResponse res)
		{
			if( !req.session ) return;
			auto usr = m_controller.getUserByName(req.session.get!string("userName"));
			callback(req, res, usr);
		}
		
		return &requestHandler;
	}
}

/** This example uses the $(D @before) annotation supported by the
	$(D vibe.web.web) framework for a concise and statically defined
	authentication approach.
*/
unittest {
	import vibe.http.router;
	import vibe.http.server;
	import vibe.web.web;

	class MyWebService {
		private {
			UserManWebAuthenticator m_auth;
		}

		this(UserManController userman)
		{
			m_auth = new UserManWebAuthenticator(userman);
		}

		// this route can be accessed publicly (/)
		void getIndex()
		{
			//render!"welcome.dt"
		}

		// the @authenticated attribute (defined below) ensures that this route
		// (/private_page) can only ever be accessed when the user is logged in
		@authenticated
		void getPrivatePage(User _user)
		{
			// render a private page with some user specific information
			//render!("private_page.dt", _user);
		}

		// Define a custom attribute for authenticated routes
		private enum authenticated = before!performAuth("_user");
		mixin PrivateAccessProxy; // needed so that performAuth can be private
		// our custom authentication routine, could return any other type, too
		private User performAuth(HTTPServerRequest req, HTTPServerResponse res)
		{
			return m_auth.performAuth(req, res);
		}
	}

	void registerMyService(URLRouter router, UserManController userman)
	{
		router.registerUserManWebInterface(userman);
		router.registerWebInterface(new MyWebService(userman));
	}
}

/** An example using a plain $(D vibe.http.router.URLRouter) based
	authentication approach.
*/
unittest {
	import std.functional; // toDelegate
	import vibe.http.router;
	import vibe.http.server;

	void getIndex(HTTPServerRequest req, HTTPServerResponse res)
	{
		//render!"welcome.dt"
	}

	void getPrivatePage(HTTPServerRequest req, HTTPServerResponse res, User user)
	{
		// render a private page with some user specific information
		//render!("private_page.dt", _user);
	}

	void registerMyService(URLRouter router, UserManController userman)
	{
		auto authenticator = new UserManWebAuthenticator(userman);
		router.registerUserManWebInterface(userman);
		router.get("/", &getIndex);
		router.any("/private_page", authenticator.auth(toDelegate(&getPrivatePage)));
	}
}


/** Web interface class for UserMan, suitable for use with $(D vibe.web.web).

	The typical approach is to use $(D registerUserManWebInterface) instead of
	directly using this class.
*/
class UserManWebInterface {
	private {
		UserManController m_controller;
		UserManWebAuthenticator m_auth;
		string m_prefix;
		SessionVar!(string, "userName") m_sessUserName;
		SessionVar!(string, "userID") m_sessUserID;
	}
	
	this(UserManController controller, string prefix = "/")
	{
		m_controller = controller;
		m_auth = new UserManWebAuthenticator(controller);
		m_prefix = prefix;
	}
	
	void getLogin(string redirect = "", string _error = "")
	{
		string error = _error;
		auto settings = m_controller.settings;
		render!("userman.login.dt", error, redirect, settings);
	}

	@errorDisplay!getLogin	
	void postLogin(string name, string password, string redirect = "")
	{
		User user;
		try {
			user = m_controller.getUserByName(name);
			enforce(testSimplePasswordHash(user.auth.passwordHash, password), "Wrong password.");
		} catch (Exception e) {
			logDebug("Error logging in: %s", e.toString().sanitize);
			throw new Exception("Invalid user/email or password.");
		}

		enforce(user.active, "The account is not yet activated.");

		m_sessUserName = user.name;
		m_sessUserID = user.id;
		.redirect(redirect.length ? redirect : m_prefix);
	}
	
	void getLogout(HTTPServerResponse res)
	{
		terminateSession();
		res.headers["Refresh"] = "3; url="~m_controller.settings.serviceUrl.toString();
		render!("userman.logout.dt");
	}

	void getRegister(string _error = "")
	{
		string error = _error;
		auto settings = m_controller.settings;
		render!("userman.register.dt", error, settings);
	}
	
	@errorDisplay!getRegister
	void postRegister(Nullable!ValidUsername name, ValidPassword password, Confirm!"password" passwordConfirmation)
	{
		string username;
		if (m_controller.settings.useUserNames) {
			enforce(!name.isNull(), "Missing user name field.");
			username = name;
		}

		m_controller.registerUser(username, password);

		if (m_controller.settings.requireAccountValidation) {
			string error;
			render!("userman.register_activate.dt", error);
		} else {
			postLogin(username, password);
		}
	}
	

	@auth
	void getProfile(HTTPServerRequest req, User _user, string _error = "")
	{
		bool useUserNames = m_controller.settings.useUserNames;
		auto user = _user;
		string error = _error;
		render!("userman.profile.dt", user, useUserNames, error);
	}
	
	@auth @errorDisplay!getProfile
	void postProfile(HTTPServerRequest req, User _user)
	{
		updateProfile(m_controller, _user, req);
		redirect(m_prefix);
	}

	// Attribute for authenticated routes
	private enum auth = before!performAuth("_user");
	mixin PrivateAccessProxy;

	private User performAuth(HTTPServerRequest req, HTTPServerResponse res)
	{
		return m_auth.performAuth(req, res);
	}
}
