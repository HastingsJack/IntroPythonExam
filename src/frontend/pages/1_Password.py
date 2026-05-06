import streamlit as st
import matplotlib.pyplot as plt
import requests

API_URL = "http://localhost:8000/password/cracking"
SECONDS_IN_YEAR = 60 * 60 * 24 * 365

st.title("Password Crack Time Estimator")

password_input = st.text_input("Enter a password")
url = "https://haveibeenpwned.com/"
st.markdown(f"Auto password check with the help of [Have I Been Pwned]({url})")

if st.button("Add/Check password"):
    response = requests.get(API_URL, params={"password": password_input})

    data = response.json()
    print(data)

    if data["data"][-1]["hibp"]:
        st.error("This password was found in the Have I Been Pwned records!")
    else:
        st.success("This password was not found in the Have I Been Pwned records.")

    passwords = []
    lengths = []
    crack_times_seconds = []
    hibp_flags = []

    for r in data["data"]:
        passwords.append(r["password"])
        lengths.append(r["length"])
        crack_times_seconds.append(r["crack_time_seconds"])
        hibp_flags.append(r["hibp"])

    # Convert seconds to years
    crack_times_years = [s / SECONDS_IN_YEAR for s in crack_times_seconds]

    # Plot
    fig, ax = plt.subplots(figsize=(10, 6))

    # Plot markers with color based on HIBP (no line)
    colors = ["red" if hibp else "blue" for hibp in hibp_flags]
    ax.scatter(lengths, crack_times_years, c=colors, s=100, zorder=3)

    # Add labels for each point
    for i in range(len(passwords)):
        ax.text(
            lengths[i],
            crack_times_years[i],
            f"{passwords[i]} ({crack_times_years[i]:.2f} yrs)",
            fontsize=9,
            ha="center",
            va="bottom",
        )

    # Log scale for y-axis
    ax.set_yscale("log")
    ax.set_xlabel("Password Length")
    ax.set_ylabel("Time to Crack (years)")
    ax.set_title("Password Length vs Time to Crack")
    ax.grid(True, which="both", ls="--", lw=0.5)

    # Optional legend
    if any(hibp_flags):
        ax.scatter([], [], color="red", label="Password found in HIBP")
        ax.scatter([], [], color="blue", label="Password not found in HIBP")
        ax.legend()

    st.pyplot(fig)
