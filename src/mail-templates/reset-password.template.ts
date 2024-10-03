export const resetPassword = (name: string, reset_link: string) => {
	return `
	<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<title>Password Reset</title>
</head>
<body>
	<h1>Password Reset</h1>
	<p>Hi, ${name}</p>
	<p>We received a request to reset your password. If you did not make this request, please ignore this email.</p>
	<p>Click the link below to reset your password:</p>
	<p><a href="${reset_link}">${reset_link}</a></p>
	<p>Thank you</p>
</body>
</html>
`;
};
