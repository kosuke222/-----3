document.addEventListener('DOMContentLoaded', function() {
	const testButton = document.createElement('test-button');
	const responseOutput = document.getElementById('response-output');
	document.getElementById('test-button').addEventListener('click', function() {
		responseOutput.textContent = "送信中";
		fetch('/api/test',{
			method: 'GET'
		})
		.then(response =>{
			if (!response.ok){
				throw new Error(`HTTP Error status: ${response.status}`);
			}
			return response.json();
		})
		.then(data => {
			responseOutput.textContent = JSON.stringify(data, null, 2);
		})
		.catch(error => {
			console.error('Fetch Error:', error);
			responseOutput.textContent = `Error: ${error.message}`;
		});
	});
});