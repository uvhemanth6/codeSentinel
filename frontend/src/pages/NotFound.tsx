import { Link } from 'react-router-dom'
import { EmptyState } from '../components/ui'

export default function NotFound() {
  return <EmptyState title="Page not found" action={<Link className="btn-primary" to="/dashboard">Back to dashboard</Link>}>The page you are looking for does not exist.</EmptyState>
}
