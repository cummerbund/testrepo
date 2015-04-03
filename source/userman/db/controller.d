/**
	Database abstraction layer

	Copyright: © 2012-2015 RejectedSoftware e.K.
	License: Subject to the terms of the General Public License version 3, as written in the included LICENSE.txt file.
	Authors: Sönke Ludwig
*/
module userman.db.controller;

public import userman.userman;
import userman.id;

import vibe.crypto.passwordhash;
import vibe.data.serialization;
import vibe.db.mongo.mongo;
import vibe.http.router;
import vibe.mail.smtp;
import vibe.stream.memory;
import vibe.templ.diet;
import vibe.utils.validation;

import std.algorithm;
import std.array;
import std.datetime;
import std.exception;
import std.random;
import std.string;


UserManController createUserManController(UserManSettings settings)
{
	import userman.db.file;
	import userman.db.mongo;
	import userman.db.redis;
	
	auto url = settings.databaseURL;
	if (url.startsWith("redis://")) return new RedisUserManController(settings);
	else if (url.startsWith("mongodb://")) return new MongoUserManController(settings);
	else if (url.startsWith("file://")) return new FileUserManController(settings);
	else throw new Exception("Unknown URL schema: "~url);
}

class UserManController {
	protected {
		UserManSettings m_settings;
	}
	
	this(UserManSettings settings)
	{	
		m_settings = settings;
	}

	@property UserManSettings settings() { return m_settings; }

	void validateUser(in ref User usr)
	{
		enforce(usr.name.length > 3, "User names must be at least 3 characters.");
	}
	
	abstract User.ID addUser(ref User usr);

	User.ID registerUser(string name, string password)
	{
		name = name.toLower();

		validatePassword(password, password);

		auto need_activation = m_settings.requireAccountValidation;
		User user;
		user.active = !need_activation;
		user.name = name;
		user.auth.method = "password";
		user.auth.passwordHash = generateSimplePasswordHash(password);

		addUser(user);
		
		return user.id;
	}


	abstract User getUser(User.ID id);

	abstract User getUserByName(string name);

	abstract void enumerateUsers(int first_user, int max_count, void delegate(ref User usr) del);

	abstract long getUserCount();

	abstract void deleteUser(User.ID user_id);

	abstract void updateUser(in ref User user);
	abstract void setPassword(User.ID user, string password);
	abstract void setProperty(User.ID user, string name, string value);

	abstract void addGroup(string name, string description);
	abstract Group getGroup(Group.ID id);
	abstract Group getGroupByName(string name);
}

struct User {
	alias .ID!User ID;
	@(.name("_id")) ID id;
	bool active;
	bool banned;
	string name;
	Group.ID[] groups;
	string activationCode;
	string resetCode;
	SysTime resetCodeExpireTime;
	AuthInfo auth;
	Json[string] properties;

	bool isInGroup(Group.ID group) const { return groups.countUntil(group) >= 0; }
}

struct Item {
	alias .ID!Item ID;
	@(.name("_id")) ID id;
	bool active;
	string title;
	string description;
	User.ID uid;
	int price;
	Currency.code currency;
	int available;
}

struct Currency {
	string code;
	int value;
}

struct AuthInfo {
	string method = "password";
	string passwordHash;
	string token;
	string secret;
	string info;
}

struct Group {
	alias .ID!Group ID;
	@(.name("_id")) ID id;
	string name;
	string description;
	@optional Json[string] properties;
}

