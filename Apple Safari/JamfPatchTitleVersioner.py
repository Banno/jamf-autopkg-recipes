#!/usr/local/autopkg/python

"""
JamfPatchTitleVersioner processor for finding the latest software version number for a Patch Title from Jamf Pro using AutoPkg
    modified from: https://github.com/jazzace/grahampugh-recipes/blob/baa5432f1378da076b44b71a9dc0d2527b4b770e/JamfUploaderProcessors/JamfPatchTitleVersioner.py
"""

import xml.etree.ElementTree as ET

from autopkglib import ProcessorError  # pylint: disable=import-error

from JamfUploaderBaseLocal import JamfUploaderBase

__all__ = ["JamfPatchTitleVersioner"]

class JamfPatchTitleVersioner(JamfUploaderBase):
    """Determines the latest software version being reported by a Jamf Pro Patch Management Title."""

    input_variables = {
        "JSS_URL": {
            "required": True,
            "description": "URL to a Jamf Pro server that the API user has write access "
            "to, optionally set as a key in the com.github.autopkg "
            "preference file.",
        },
        "API_USERNAME": {
            "required": False,
            "description": "Username of account with appropriate access to "
            "jss, optionally set as a key in the com.github.autopkg "
            "preference file.",
        },
        "API_PASSWORD": {
            "required": False,
            "description": "Password of api user, optionally set as a key in "
            "the com.github.autopkg preference file.",
        },
        "CLIENT_ID": {
            "required": False,
            "description": "Client ID with access to "
            "jss, optionally set as a key in the com.github.autopkg "
            "preference file.",
        },
        "CLIENT_SECRET": {
            "required": False,
            "description": "Secret associated with the Client ID, optionally set as a key in "
            "the com.github.autopkg preference file.",
        },
        "patch_softwaretitle": {
            "required": True,
            "description": (
                "Name of the patch software title (e.g. 'Mozilla Firefox') used in Jamf. "
            ),
            "default": "",
        },
    }

    output_variables = {
        "latest_patch_version": {
            "description": "The latest version number of the software reported by the Patch Title."
        },
    }

    object_type = "patch_software_title"

    def latest_patch_version(
        self,
        jamf_url,
        patch_softwaretitle_id,
        token
    ) -> str:
        """Returns the newest software version number for the Patch Title ID passed"""
        self.output("Looking up latest version from patch software title (by ID)...")

        # Get current software title
        url = "{}/{}/id/{}".format(
            jamf_url, self.api_endpoints(self.object_type), patch_softwaretitle_id
        )

        # "GET" patch title feed.
        r = self.curl(
            request="GET", url=url, token=token, endpoint_type=self.object_type, accept_header="xml"
        )

        if r.status_code != 200:
            raise ProcessorError("ERROR: Could not fetch patch software title.")

        # Parse response as xml
        try:
            patch_softwaretitle_xml = ET.fromstring(r.output)
        except ET.ParseError as xml_error:
            raise ProcessorError from xml_error

        # Get first match of all the versions listed in the
        # software title to report the 'latest version'.
        latest_version = patch_softwaretitle_xml.find("versions/version/software_version").text
        return latest_version

    def main(self):
        jamf_url = self.env.get("JSS_URL")
        jamf_user = self.env.get("API_USERNAME")
        jamf_password = self.env.get("API_PASSWORD")
        client_id = self.env.get("CLIENT_ID")
        client_secret = self.env.get("CLIENT_SECRET")
        patch_softwaretitle = self.env.get("patch_softwaretitle")

        self.output(
            f"Checking for existing '{patch_softwaretitle}' on {jamf_url}"
        )

        # get token using oauth or basic auth depending on the credentials given
        if jamf_url:
            token = self.handle_api_auth(
                jamf_url,
                jamf_user=jamf_user,
                password=jamf_password,
                client_id=client_id,
                client_secret=client_secret,
            )
        else:
            raise ProcessorError("ERROR: Jamf Pro URL not supplied")

        # Find the ID for the Patch Title
        obj_name = patch_softwaretitle
        patch_softwaretitle_id = self.get_api_obj_id_from_name(jamf_url, obj_name, self.object_type, token)

        if not patch_softwaretitle_id:
            raise ProcessorError(
                f"ERROR: Couldn't find patch software title with name '{patch_softwaretitle}'.",
            )
        self.env["patch_softwaretitle_id"] = patch_softwaretitle_id

        # fetch the latest version reported by the Patch Title
        patch_version = self.latest_patch_version(
            jamf_url,
            patch_softwaretitle_id,
            token,
        )

        # Set Output Variable
        self.env["latest_patch_version"] = patch_version

if __name__ == "__main__":
    PROCESSOR = JamfPatchTitleVersioner()
    PROCESSOR.execute_shell()
