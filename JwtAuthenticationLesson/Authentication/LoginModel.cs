using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace JwtAuthenticationLesson.Authentication
{
	public class LoginModel
	{
		[Required(ErrorMessage = "Username is required")]
		public string Username { set; get; }

		[Required(ErrorMessage = "Password is required")]
		public string Password { set; get; }
	}
}