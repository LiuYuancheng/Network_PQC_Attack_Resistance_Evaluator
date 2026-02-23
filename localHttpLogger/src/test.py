import requests

# The URL you want to send the request to
#url = "https://api.github.com"
url = "https://www.baidu.com/"
url = "https://123.com/"
url = "https://y.arin.net?"
try:
    # Send the GET request and store the response
    response = requests.get(url)

    # Check if the request was successful (status code 200-299)
    response.raise_for_status()

    # Access various parts of the response object
    print(f"Status Code: {response.status_code}")
    print(f"Content Type: {response.headers['Content-Type']}")
    print("Response JSON:")

    # Parse the response body as JSON into a Python dictionary
    user_data = response.json()
    print(user_data['login'])

except requests.exceptions.RequestException as e:
    print(f"An error occurred: {e}")

