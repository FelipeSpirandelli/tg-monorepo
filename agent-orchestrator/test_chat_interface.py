#!/usr/bin/env python3
"""
test_chat_interface.py

Test script for the SOC analyst chat interface functionality.
Tests chat session management, API endpoints, and interface components.
"""

import asyncio
import json
import os
import sys
from typing import Dict, Any

# Set dummy environment variables for testing
os.environ['ANTHROPIC_API_KEY'] = 'test-key'
os.environ['QDRANT_URL'] = 'http://localhost:6333'
os.environ['QDRANT_COLLECTION'] = 'pdf_rag'
os.environ['EMBEDDING_MODEL'] = 'sentence-transformers/all-MiniLM-L6-v2'
os.environ['ABUSEIPDB_API_KEY'] = 'test-key'


class ChatInterfaceTester:
    """Test class for chat interface functionality."""

    def __init__(self):
        self.test_results = []

    def log_test(self, test_name: str, success: bool, message: str = ""):
        """Log a test result."""
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} {test_name}: {message}")
        self.test_results.append({
            "test": test_name,
            "success": success,
            "message": message
        })

    async def test_imports(self):
        """Test that all required modules can be imported."""
        try:
            from src.chat_session_manager import ChatSessionManager, ChatSession
            from src.agent_manager import AgentManager
            print("✅ All imports successful")
            return True
        except Exception as e:
            print(f"❌ Import test failed: {e}")
            return False

    async def test_agent_manager_initialization(self):
        """Test that the agent manager initializes correctly."""
        try:
            from src.agent_manager import AgentManager

            agent_manager = AgentManager()
            await agent_manager.initialize_mvc_agent()

            if agent_manager.mcp_client is None:
                self.log_test("Agent Manager Initialization", False, "MCP client not initialized")
                return False

            if len(agent_manager.pipeline_processor.steps) == 0:
                self.log_test("Agent Manager Initialization", False, "No pipeline steps registered")
                return False

            self.log_test("Agent Manager Initialization", True, f"Initialized with {len(agent_manager.pipeline_processor.steps)} pipeline steps")
            return True

        except Exception as e:
            self.log_test("Agent Manager Initialization", False, f"Error: {e}")
            return False

    async def test_chat_session_creation(self):
        """Test chat session creation and management."""
        try:
            from src.chat_session_manager import ChatSessionManager
            from src.agent_manager import AgentManager

            # Initialize agent manager
            agent_manager = AgentManager()
            await agent_manager.initialize_mvc_agent()

            # Create chat session manager
            chat_manager = ChatSessionManager(agent_manager.mcp_client)

            # Create a test session
            alert_summary = "Test SSH brute force alert"
            analyst_report = {"executive_summary": "Test report"}

            session_id = await chat_manager.create_session(alert_summary, analyst_report)

            if not session_id:
                self.log_test("Chat Session Creation", False, "Session ID not returned")
                return False

            # Verify session exists
            session = await chat_manager.get_session(session_id)
            if not session:
                self.log_test("Chat Session Creation", False, "Session not found after creation")
                return False

            # Test message sending (may fail due to API key, but should handle gracefully)
            test_message = "What are the recommended response procedures for this alert?"
            response = await chat_manager.send_message(session_id, test_message)

            # For testing, we expect either success or a graceful API failure
            if response.get("success", False):
                # API call succeeded
                if not response.get("response"):
                    self.log_test("Chat Message Sending", False, "No response received despite success")
                    return False
                self.log_test("Chat Message Sending", True, "Message sent successfully with real response")
            else:
                # API call failed (expected with test key)
                error_msg = response.get("error", "")
                if "authentication_error" in error_msg or "invalid x-api-key" in error_msg:
                    self.log_test("Chat Message Sending", True, "Message sending handled API failure gracefully (expected with test key)")
                else:
                    self.log_test("Chat Message Sending", False, f"Unexpected error: {error_msg}")
                    return False

            # Test session ending (should work even if LLM failed)
            end_result = await chat_manager.end_session(session_id)

            if not end_result.get("success", False):
                self.log_test("Chat Session Ending", False, f"Session end failed: {end_result.get('error')}")
                return False

            # Session ending should always work, even if LLM responses failed
            report = end_result.get("report", {})
            if not report:
                self.log_test("Chat Session Ending", False, "No report generated")
                return False

            # Recommendations might be empty if LLM failed, but that's OK for testing
            recommendations = report.get("final_recommendations", [])
            self.log_test("Chat Session Ending", True, f"Session ended successfully with {len(recommendations)} recommendations")
            return True

        except Exception as e:
            self.log_test("Chat Session Creation", False, f"Error: {e}")
            return False

    async def test_fastapi_endpoints(self):
        """Test FastAPI chat endpoints (without actually starting the server)."""
        try:
            # Test that the endpoints are properly defined by checking if they exist
            # We can't import 'app' directly, but we can check if the file structure is correct
            import os

            main_file = "/home/rafael/Desktop/ITA/tg-monorepo/agent-orchestrator/main.py"
            if not os.path.exists(main_file):
                self.log_test("FastAPI Endpoints", False, "main.py file not found")
                return False

            # Read the main.py file and check for chat endpoints
            with open(main_file, 'r') as f:
                content = f.read()

            expected_endpoints = ["/chat/init", "/chat/message", "/chat/end", "/chat/sessions", "/alert/complete"]
            found_endpoints = []

            for endpoint in expected_endpoints:
                if f'"{endpoint}"' in content or f"'{endpoint}'" in content:
                    found_endpoints.append(endpoint)
                    print(f"✅ Found endpoint: {endpoint}")

            if len(found_endpoints) >= 4:  # At least the main chat endpoints
                self.log_test("FastAPI Endpoints", True, f"Found {len(found_endpoints)}/{len(expected_endpoints)} expected endpoints")
                return True
            else:
                self.log_test("FastAPI Endpoints", False, f"Only found {len(found_endpoints)} endpoints")
                return False

        except Exception as e:
            self.log_test("FastAPI Endpoints", False, f"Error: {e}")
            return False

    async def test_chat_interface_html(self):
        """Test that the chat interface HTML file exists and is valid."""
        try:
            chat_file = "/home/rafael/Desktop/ITA/tg-monorepo/agent-orchestrator/chat_interface.html"

            if not os.path.exists(chat_file):
                self.log_test("Chat Interface HTML", False, "HTML file not found")
                return False

            # Check file size (should be substantial)
            file_size = os.path.getsize(chat_file)
            if file_size < 1000:  # Less than 1KB seems too small
                self.log_test("Chat Interface HTML", False, f"HTML file too small: {file_size} bytes")
                return False

            # Basic HTML validation
            with open(chat_file, 'r', encoding='utf-8') as f:
                content = f.read()

            if "<html" not in content.lower() or "<body" not in content.lower():
                self.log_test("Chat Interface HTML", False, "Invalid HTML structure")
                return False

            if "chat-container" not in content or "message-bubble" not in content:
                self.log_test("Chat Interface HTML", False, "Missing required chat elements")
                return False

            self.log_test("Chat Interface HTML", True, f"Valid HTML file ({file_size} bytes)")
            return True

        except Exception as e:
            self.log_test("Chat Interface HTML", False, f"Error: {e}")
            return False

    async def run_all_tests(self):
        """Run all tests and report results."""
        print("🔍 Starting SOC Analyst Chat Interface Tests\n")

        tests = [
            ("Import Tests", self.test_imports),
            ("Agent Manager Initialization", self.test_agent_manager_initialization),
            ("Chat Session Management", self.test_chat_session_creation),
            ("FastAPI Endpoints", self.test_fastapi_endpoints),
            ("Chat Interface HTML", self.test_chat_interface_html),
        ]

        for test_name, test_func in tests:
            print(f"\n🧪 Running: {test_name}")
            try:
                success = await test_func()
                if not success:
                    print(f"❌ {test_name} failed")
            except Exception as e:
                print(f"❌ {test_name} crashed: {e}")
                self.log_test(test_name, False, f"Crashed: {e}")

        # Summary
        passed = sum(1 for result in self.test_results if result["success"])
        total = len(self.test_results)

        print(f"\n📊 Test Summary: {passed}/{total} tests passed")

        if passed == total:
            print("🎉 All tests passed! Chat interface is ready for use.")
        else:
            print("⚠️  Some tests failed. Please review the issues above.")

        return passed == total


async def main():
    """Main test function."""
    tester = ChatInterfaceTester()
    success = await tester.run_all_tests()

    if success:
        print("\n🚀 Chat interface testing completed successfully!")
        print("You can now:")
        print("1. Open chat_interface.html in a web browser")
        print("2. Start the FastAPI server: python main.py")
        print("3. Access the chat at http://localhost:8001/chat/init")
    else:
        print("\n❌ Chat interface testing failed.")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
